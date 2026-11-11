package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"tunnelslate/internal/config"
	"tunnelslate/internal/store"
)

func fixture(t *testing.T) (http.Handler, *store.Store, config.Config) {
	t.Helper()
	cfg := config.Config{DBPath: filepath.Join(t.TempDir(), "desk.sqlite"), WebDir: t.TempDir(), PublicURL: "https://desk.test", CookieSecure: true, SessionTTL: time.Hour}
	db, err := store.Open(context.Background(), cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.DB.Close() })
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("INSERT INTO admins(id,username,password_hash,created_at) VALUES (1,?,?,?)", "admin", string(hash), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	handler, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	return handler, db, cfg
}
func request(h http.Handler, method, path, body string, cookie *http.Cookie, csrf, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func signIn(t *testing.T, h http.Handler) (*http.Cookie, string) {
	t.Helper()
	w := request(h, "POST", "/api/auth/login", `{"username":"admin","password":"correct-password-123"}`, nil, "", "https://desk.test")
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("expected session cookie")
	}
	var body struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return cookies[0], body.CSRF
}

func TestProtectedRoutes(t *testing.T) {
	h, _, _ := fixture(t)
	for _, path := range []string{"/api/auth/session", "/api/dashboard", "/api/clients", "/api/certificates", "/api/audit", "/api/settings", "/api/devices", "/api/operations", "/api/connections"} {
		w := request(h, "GET", path, "", nil, "", "")
		if w.Code != 401 {
			t.Errorf("%s = %d", path, w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Error("sensitive API must not be cached")
		}
	}
}

func TestPKIInitializationRequiresLoginAndCSRF(t *testing.T) {
	h, db, _ := fixture(t)
	if w := request(h, "POST", "/api/pki/initialize", `{}`, nil, "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	cookie, csrf := signIn(t, h)
	for _, test := range []struct{ token, origin string }{{"", "https://desk.test"}, {csrf, "https://evil.test"}} {
		if w := request(h, "POST", "/api/pki/initialize", `{}`, cookie, test.token, test.origin); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	if w := request(h, "POST", "/api/pki/initialize", `{"reset":true}`, cookie, csrf, "https://desk.test"); w.Code != 400 {
		t.Fatal(w.Code)
	}
	var count int
	if err := db.DB.QueryRow("SELECT count(*) FROM pki_bootstrap").Scan(&count); err != nil || count != 0 {
		t.Fatalf("unauthorized initialization mutated state: count=%d err=%v", count, err)
	}
}

func TestBasePathRoutingCookiesAndFrontend(t *testing.T) {
	_, db, cfg := fixture(t)
	cfg.BasePath = "/ovpn"
	if err := os.WriteFile(filepath.Join(cfg.WebDir, "index.html"), []byte(`<html><head></head><body>desk</body></html>`), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(h, "GET", "/ovpn", "", nil, "", ""); w.Code != 308 || w.Header().Get("Location") != "/ovpn/" {
		t.Fatal("base path must redirect to trailing slash")
	}
	for _, path := range []string{"/ovpn/", "/ovpn/settings/deep"} {
		w := request(h, "GET", path, "", nil, "", "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), `<base href="/ovpn/">`) {
			t.Fatalf("frontend path=%s code=%d", path, w.Code)
		}
	}
	if w := request(h, "GET", "/healthz", "", nil, "", ""); w.Code != 200 {
		t.Fatal("Docker healthcheck failed under base path")
	}
	if w := request(h, "GET", "/api/settings", "", nil, "", ""); w.Code != 404 {
		t.Fatal("API leaked outside base path")
	}
	if w := request(h, "GET", "/ovpn/api/settings", "", nil, "", ""); w.Code != 401 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("base path API auth/cache policy")
	}
	w := request(h, "POST", "/ovpn/api/auth/login", `{"username":"admin","password":"correct-password-123"}`, nil, "", "https://desk.test")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	cookie := w.Result().Cookies()[0]
	if cookie.Path != "/ovpn/" {
		t.Fatal("cookie path escaped application")
	}
	var body struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	logout := request(h, "POST", "/ovpn/api/auth/logout", "", cookie, body.CSRF, "https://desk.test")
	if logout.Code != 200 || logout.Result().Cookies()[0].Path != "/ovpn/" {
		t.Fatal("logout cookie path mismatch")
	}
}
func TestLoginSessionCSRFAndLogout(t *testing.T) {
	h, db, cfg := fixture(t)
	cookie, csrf := signIn(t, h)
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe cookie: %+v", cookie)
	}
	var saved string
	if err := db.DB.QueryRow("SELECT token_hash FROM sessions").Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if saved == cookie.Value || saved != tokenHash(cookie.Value) {
		t.Fatal("raw session token stored")
	}
	if w := request(h, "GET", "/api/dashboard", "", cookie, "", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	// A new handler (process restart) must accept the persisted session.
	restarted, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(restarted, "GET", "/api/auth/session", "", cookie, "", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(h, "POST", "/api/auth/logout", "", cookie, "", "https://desk.test"); w.Code != 403 {
		t.Fatalf("missing CSRF: %d", w.Code)
	}
	if w := request(h, "POST", "/api/auth/logout", "", cookie, csrf, "https://evil.test"); w.Code != 403 {
		t.Fatalf("wrong origin: %d", w.Code)
	}
	if w := request(h, "POST", "/api/auth/logout", "", cookie, csrf, "https://desk.test"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(h, "GET", "/api/auth/session", "", cookie, "", ""); w.Code != 401 {
		t.Fatal("logged out session still accepted")
	}
	var count int
	if err := db.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action IN ('auth.login','auth.logout')").Scan(&count); err != nil || count != 2 {
		t.Fatalf("audit count %d, err %v", count, err)
	}
}
func TestLoginFailuresAndRateLimit(t *testing.T) {
	h, _, _ := fixture(t)
	good := `{"username":"admin","password":"correct-password-123"}`
	if w := request(h, "POST", "/api/auth/login", good, nil, "", "https://evil.test"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	for i := 0; i < 5; i++ {
		w := request(h, "POST", "/api/auth/login", `{"username":"admin","password":"wrong-password"}`, nil, "", "")
		want := 401
		if i == 4 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	if w := request(h, "POST", "/api/auth/login", good, nil, "", ""); w.Code != 429 {
		t.Fatalf("limit: %d", w.Code)
	}
}
func TestExpiredSessionAndBootstrapDoesNotReset(t *testing.T) {
	h, db, _ := fixture(t)
	cookie, _ := signIn(t, h)
	if err := db.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	var username string
	if err := db.DB.QueryRow("SELECT username FROM admins").Scan(&username); err != nil || username != "admin" {
		t.Fatal("bootstrap reset administrator")
	}
	if _, err := db.DB.Exec("UPDATE sessions SET expires_at=?", time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if w := request(h, "GET", "/api/auth/session", "", cookie, "", ""); w.Code != 401 {
		t.Fatal("expired session accepted")
	}
}
func TestScaffoldReportsUnavailableVPNAndEmptyLists(t *testing.T) {
	h, _, _ := fixture(t)
	cookie, _ := signIn(t, h)
	for _, path := range []string{"/api/clients", "/api/certificates"} {
		w := request(h, "GET", path, "", cookie, "", "")
		if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	w := request(h, "GET", "/api/dashboard", "", cookie, "", "")
	if !strings.Contains(w.Body.String(), `"state":"not_configured"`) || !strings.Contains(w.Body.String(), `"connected_clients":null`) {
		t.Fatal(w.Body.String())
	}
	if w := request(h, "POST", "/api/clients", `{}`, cookie, "", ""); w.Code >= 200 && w.Code < 300 {
		t.Fatal("unimplemented mutation returned success")
	}
	if w := request(h, "GET", "/api/no-such-endpoint", "", cookie, "", ""); w.Code != 404 {
		t.Fatal("API fallback must be 404")
	}
	if w := request(h, "GET", "/healthz", "", nil, "", ""); w.Code != 200 {
		t.Fatal("database readiness failed")
	}
}
