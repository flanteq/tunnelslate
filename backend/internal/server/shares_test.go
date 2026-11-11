package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shareRequest(h http.Handler, method, path, body string, cookie *http.Cookie, csrf, origin, key string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Idempotency-Key", key)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func newShare(t *testing.T, h http.Handler, admin *http.Cookie, csrf, client string, replace bool) string {
	t.Helper()
	w := request(h, "POST", "/api/clients/"+client+"/link", fmt.Sprintf(`{"replace":%t}`, replace), admin, csrf, "https://desk.test")
	if w.Code != 200 {
		t.Fatalf("create share: %d %s", w.Code, w.Body.String())
	}
	var result struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(result.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "desk.test" || u.Path != "/profiles/" || u.RawQuery != "" || !shareTokenPattern.MatchString(u.Fragment) {
		t.Fatal("invalid share URL structure")
	}
	return u.Fragment
}
func exchange(t *testing.T, h http.Handler, token string) (*http.Cookie, string) {
	t.Helper()
	w := request(h, "POST", "/api/share/exchange", `{"token":"`+token+`"}`, nil, "", "https://desk.test")
	if w.Code != 200 {
		t.Fatalf("exchange: %d %s", w.Code, w.Body.String())
	}
	var body struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != shareCookieName || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/api/share/" || cookies[0].MaxAge != 1800 {
		t.Fatal("unsafe client cookie")
	}
	return cookies[0], body.CSRF
}
func TestClientLinkLifecycleAndSeparation(t *testing.T) {
	h, db, _ := fixture(t)
	admin, csrf := signIn(t, h)
	if _, err := db.DB.Exec(`INSERT INTO clients(id,name,created_at) VALUES ('alice','Alice',1),('bob','Bob',1); INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES ('phone','alice','Phone','device-phone',1),('laptop','bob','Laptop','device-laptop',1)`); err != nil {
		t.Fatal(err)
	}
	var count int
	db.DB.QueryRow("SELECT count(*) FROM client_links").Scan(&count)
	if count != 0 {
		t.Fatal("links must be optional")
	}
	token := newShare(t, h, admin, csrf, "alice", false)
	var hash string
	if err := db.DB.QueryRow("SELECT token_hash FROM client_links WHERE client_id='alice'").Scan(&hash); err != nil || hash != tokenHash(token) || hash == token {
		t.Fatal("raw token persisted")
	}
	public, publicCSRF := exchange(t, h, token)
	second, _ := exchange(t, h, token)
	w := request(h, "GET", "/api/share/devices", "", public, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Phone") || strings.Contains(w.Body.String(), "Laptop") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("profile list isolation/cache policy", w.Code)
	}
	for _, path := range []string{"/api/auth/session", "/api/clients", "/api/audit", "/api/events", "/api/settings"} {
		if w := request(h, "GET", path, "", public, "", ""); w.Code != 401 {
			t.Fatal("client session authorized admin API", path, w.Code)
		}
	}
	if w := request(h, "GET", "/api/share/devices", "", admin, "", ""); w.Code != 401 {
		t.Fatal("admin cookie authorized public API")
	}
	if w := request(h, "GET", "/api/share/devices/laptop/profile", "", public, "", ""); w.Code != 404 {
		t.Fatal("cross-client download", w.Code)
	}
	for _, origin := range []string{"", "https://evil.test"} {
		if w := request(h, "POST", "/api/share/exchange", `{"token":"`+token+`"}`, nil, "", origin); w.Code != 403 {
			t.Fatal("exchange origin", w.Code)
		}
	}
	if w := shareRequest(h, "POST", "/api/share/compromised", "{}", public, publicCSRF, "https://evil.test", "report-test-00001"); w.Code != 403 {
		t.Fatal("panic origin", w.Code)
	}
	if w := shareRequest(h, "POST", "/api/share/compromised", "{}", public, "", "https://desk.test", "report-test-00001"); w.Code != 403 {
		t.Fatal("panic csrf", w.Code)
	}
	newToken := newShare(t, h, admin, csrf, "alice", true)
	if newToken == token {
		t.Fatal("token reused")
	}
	for _, cookie := range []*http.Cookie{public, second} {
		if w := request(h, "GET", "/api/share/session", "", cookie, "", ""); w.Code != 401 {
			t.Fatal("rotation retained a session")
		}
	}
	if w := request(h, "POST", "/api/share/exchange", `{"token":"`+token+`"}`, nil, "", "https://desk.test"); w.Code != 401 {
		t.Fatal("old token survived")
	}
	public, _ = exchange(t, h, newToken)
	if w := request(h, "GET", "/api/clients", "", admin, "", ""); w.Code != 200 || strings.Contains(w.Body.String(), newToken) || strings.Contains(w.Body.String(), hash) {
		t.Fatal("link material leaked in client API")
	}
	if w := request(h, "POST", "/api/clients/alice/link/delete", "{}", admin, csrf, "https://desk.test"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(h, "GET", "/api/share/session", "", public, "", ""); w.Code != 401 {
		t.Fatal("deleted link session survived")
	}
}
func TestClientCompromiseQueuesWithoutPKIAndAuditsCritical(t *testing.T) {
	h, db, _ := fixture(t)
	admin, csrf := signIn(t, h)
	db.DB.Exec(`INSERT INTO clients(id,name,created_at) VALUES ('alice','Alice',1)`)
	token := newShare(t, h, admin, csrf, "alice", false)
	public, publicCSRF := exchange(t, h, token)
	second, _ := exchange(t, h, token)
	w := shareRequest(h, "POST", "/api/share/compromised", "{}", public, publicCSRF, "https://desk.test", "critical-report-0001")
	if w.Code != 202 || strings.Contains(w.Body.String(), "url") {
		t.Fatal("panic did not accept durable revocation", w.Code, w.Body.String())
	}
	var n int
	for _, table := range []string{"client_links", "client_link_sessions"} {
		if err := db.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatal("panic retained credentials", table, err)
		}
	}
	if err := db.DB.QueryRow("SELECT count(*) FROM operations WHERE kind='revoke_client' AND state='pending' AND client_id='alice'").Scan(&n); err != nil || n != 1 {
		t.Fatal("missing durable queued revocation", err)
	}
	if err := db.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='client.link.compromised' AND severity='CRITICAL' AND actor='client-link:alice' AND target='alice'").Scan(&n); err != nil || n != 1 {
		t.Fatal("missing immediate critical audit", err)
	}
	for _, cookie := range []*http.Cookie{public, second} {
		if request(h, "GET", "/api/share/session", "", cookie, "", "").Code != 401 {
			t.Fatal("session survived compromise")
		}
	}
	if w := request(h, "POST", "/api/clients/alice/link", `{"replace":false}`, admin, csrf, "https://desk.test"); w.Code != 409 {
		t.Fatal("link recreated before revocation finished", w.Code)
	}
	w = request(h, "GET", "/api/audit", "", admin, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"severity":"CRITICAL"`) || !strings.Contains(w.Body.String(), `"target_name":"Alice"`) {
		t.Fatal("critical audit not exposed", w.Code, w.Body.String())
	}
}
func TestClientCompromiseAuditFailureRollsBack(t *testing.T) {
	h, db, _ := fixture(t)
	admin, csrf := signIn(t, h)
	db.DB.Exec(`INSERT INTO clients(id,name,created_at) VALUES ('alice','Alice',1)`)
	token := newShare(t, h, admin, csrf, "alice", false)
	public, publicCSRF := exchange(t, h, token)
	db.DB.Exec(`CREATE TRIGGER audit_failure BEFORE INSERT ON audit_events WHEN NEW.action='client.link.compromised' BEGIN SELECT RAISE(FAIL,'test audit failure'); END`)
	w := shareRequest(h, "POST", "/api/share/compromised", "{}", public, publicCSRF, "https://desk.test", "critical-report-fail1")
	if w.Code != 500 {
		t.Fatal("audit failure accepted", w.Code)
	}
	if request(h, "GET", "/api/share/session", "", public, "", "").Code != 200 {
		t.Fatal("transaction did not restore client access")
	}
	var n int
	db.DB.QueryRow("SELECT count(*) FROM operations WHERE kind='revoke_client'").Scan(&n)
	if n != 0 {
		t.Fatal("failed transaction left an operation")
	}
}
func TestClientSessionsExpiryDisableAndBasePath(t *testing.T) {
	h, db, cfg := fixture(t)
	admin, csrf := signIn(t, h)
	db.DB.Exec(`INSERT INTO clients(id,name,created_at) VALUES ('alice','Alice',1)`)
	token := newShare(t, h, admin, csrf, "alice", false)
	public, _ := exchange(t, h, token)
	db.DB.Exec("UPDATE client_link_sessions SET expires_at=?", time.Now().Add(-time.Second).Unix())
	if request(h, "GET", "/api/share/session", "", public, "", "").Code != 401 {
		t.Fatal("expired session accepted")
	}
	public, _ = exchange(t, h, token)
	db.DB.Exec("UPDATE clients SET disabled=1 WHERE id='alice'")
	if request(h, "GET", "/api/share/session", "", public, "", "").Code != 401 {
		t.Fatal("disabled client accepted")
	}
	db.DB.Exec("UPDATE clients SET disabled=0 WHERE id='alice'")
	cfg.BasePath = "/ovpn"
	h, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	w := request(h, "POST", "/ovpn/api/share/exchange", `{"token":"`+token+`"}`, nil, "", "https://desk.test")
	if w.Code != 200 || w.Result().Cookies()[0].Path != "/ovpn/api/share/" {
		t.Fatal("base path cookie", w.Code)
	}
	if request(h, "GET", "/api/share/session", "", public, "", "").Code != 404 {
		t.Fatal("public API escaped base path")
	}
}

func TestAdminCompromiseIsIdempotentAndCritical(t *testing.T) {
	h, db, _ := fixture(t)
	admin, csrf := signIn(t, h)
	db.DB.Exec(`INSERT INTO clients(id,name,created_at) VALUES ('alice','Alice',1)`)
	_ = newShare(t, h, admin, csrf, "alice", false)
	for i := 0; i < 2; i++ {
		w := shareRequest(h, "POST", "/api/clients/alice/link/compromised", "{}", admin, csrf, "https://desk.test", "admin-compromise-key1")
		if w.Code != 202 {
			t.Fatal("admin report/replay", w.Code, w.Body.String())
		}
	}
	var n int
	if err := db.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='client.link.compromised' AND severity='CRITICAL' AND actor='admin'").Scan(&n); err != nil || n != 1 {
		t.Fatal("duplicate/missing critical event", err, n)
	}
}
func TestClientLinkFinalResponseRevalidatesAccess(t *testing.T) {
	h, db, _ := fixture(t)
	s := h.(*Server)
	admin, csrf := signIn(t, h)
	db.DB.Exec(`INSERT INTO clients(id,name,created_at) VALUES ('alice','Alice',1)`)
	token := newShare(t, h, admin, csrf, "alice", false)
	public, _ := exchange(t, h, token)
	var exposed bool
	handler := s.shareAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate deletion after middleware authentication and before profile bytes.
		db.LinkMu.Lock()
		_, err := db.DB.Exec("DELETE FROM client_links WHERE client_id='alice'")
		db.LinkMu.Unlock()
		if err != nil {
			t.Error(err)
		}
		s.shareResponse(w, r, func() { exposed = true; w.Write([]byte("private-key")) })
	}))
	w := request(handler, "GET", "/api/share/devices/phone/profile", "", public, "", "")
	if w.Code != 401 || exposed {
		t.Fatal("stale authorization exposed secret", w.Code)
	}
}
func TestClientLinkExchangeRateLimitAndBadTokens(t *testing.T) {
	h, _, _ := fixture(t)
	for i := 0; i < 30; i++ {
		w := request(h, "POST", "/api/share/exchange", `{"token":"`+strings.Repeat("a", 64)+`"}`, nil, "", "https://desk.test")
		if w.Code != 401 {
			t.Fatal("bad token status", w.Code)
		}
	}
	w := request(h, "POST", "/api/share/exchange", `{"token":"`+strings.Repeat("b", 64)+`"}`, nil, "", "https://desk.test")
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("exchange not rate limited", w.Code)
	}
}

func TestClientPortalHasBaseAndPrivateDocumentPolicy(t *testing.T) {
	_, db, cfg := fixture(t)
	cfg.BasePath = "/ovpn"
	if err := os.WriteFile(filepath.Join(cfg.WebDir, "index.html"), []byte("<html><head></head><body>app</body></html>"), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	w := request(h, "GET", "/ovpn/profiles/", "", nil, "", "")
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Robots-Tag") == "" || !strings.Contains(w.Body.String(), `<base href="/ovpn/">`) || !strings.Contains(w.Header().Get("Content-Security-Policy"), "base-uri 'self'") {
		t.Fatal("portal base path/security headers", w.Code)
	}
}

func TestClientLinkDownloadsCurrentRealProfileAndStopsAfterReport(t *testing.T) {
	if _, err := os.Stat("/usr/share/easy-rsa/easyrsa"); err != nil {
		t.Skip("requires Docker backend test image")
	}
	_, db, cfg := fixture(t)
	cfg.PKIDir = t.TempDir()
	cfg.OpenVPNDir = t.TempDir()
	cfg.CCDDir = t.TempDir()
	cfg.ManagementSocket = filepath.Join(t.TempDir(), "missing.sock")
	s, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.pki.Initialize(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("INSERT INTO clients(id,name,created_at) VALUES ('alice','Alice',1)"); err != nil {
		t.Fatal(err)
	}
	issued, err := s.pki.Start(ctx, "admin", "public-profile-issue1", "issue", "alice", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	admin, csrf := signIn(t, s)
	token := newShare(t, s, admin, csrf, "alice", false)
	public, publicCSRF := exchange(t, s, token)
	w := request(s, "GET", "/api/share/devices", "", public, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"downloadable":true`) {
		t.Fatal("valid profile not advertised", w.Code, w.Body.String())
	}
	w = request(s, "GET", "/api/share/devices/"+issued.DeviceID+"/profile", "", public, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<key>") || !strings.Contains(w.Body.String(), "<cert>") || !strings.Contains(w.Header().Get("Content-Disposition"), "Alice-Phone-") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("real profile response invalid", w.Code)
	}
	w = shareRequest(s, "POST", "/api/share/compromised", "{}", public, publicCSRF, cfg.PublicURL, "public-profile-panic1")
	if w.Code != 202 {
		t.Fatal("report", w.Code)
	}
	// PKI has not run yet, but the download is already forbidden.
	w = request(s, "GET", "/api/share/devices/"+issued.DeviceID+"/profile", "", public, "", "")
	if w.Code != 401 || strings.Contains(w.Body.String(), "<key>") {
		t.Fatal("profile leaked after report", w.Code)
	}
}

func TestClientLinkNewTokenReplacesCompromisedSessionCookie(t *testing.T) {
	h, db, _ := fixture(t)
	admin, csrf := signIn(t, h)
	if _, err := db.DB.Exec("INSERT INTO clients(id,name,created_at) VALUES ('alice','Alice',1)"); err != nil {
		t.Fatal(err)
	}
	oldToken := newShare(t, h, admin, csrf, "alice", false)
	oldCookie, publicCSRF := exchange(t, h, oldToken)
	w := shareRequest(h, "POST", "/api/share/compromised", "{}", oldCookie, publicCSRF, "https://desk.test", "replace-compromised1")
	if w.Code != 202 {
		t.Fatal("compromise request", w.Code)
	}
	// Certificate recovery is tested in pki. Here finish the queued operation to
	// isolate session replacement from the certificate lifecycle.
	if _, err := db.DB.Exec("UPDATE operations SET state='succeeded',step='complete' WHERE kind='revoke_client'"); err != nil {
		t.Fatal(err)
	}
	newToken := newShare(t, h, admin, csrf, "alice", false)
	w = request(h, "POST", "/api/share/exchange", `{"token":"`+newToken+`"}`, oldCookie, "", "https://desk.test")
	if w.Code != 200 {
		t.Fatal("stale cookie prevented new token exchange", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == oldCookie.Value {
		t.Fatal("new session cookie was not issued")
	}
	if w := request(h, "GET", "/api/share/session", "", cookies[0], "", ""); w.Code != 200 {
		t.Fatal("new session unavailable", w.Code)
	}
	if w := request(h, "GET", "/api/share/session", "", oldCookie, "", ""); w.Code != 401 {
		t.Fatal("compromised session revived", w.Code)
	}
	if w := request(h, "POST", "/api/share/exchange", `{"token":"`+oldToken+`"}`, cookies[0], "", "https://desk.test"); w.Code != 401 {
		t.Fatal("invalid token fell back to a valid cookie", w.Code)
	}
}
