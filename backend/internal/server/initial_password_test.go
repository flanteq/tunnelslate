package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tunnelslate/internal/passwordhash"

	"tunnelslate/internal/store"
)

func initialPasswordFixture(t *testing.T, prefix string) (*Server, *store.Store, string) {
	t.Helper()
	_, db, cfg := fixture(t)
	if _, err := db.DB.Exec("DELETE FROM admins"); err != nil {
		t.Fatal(err)
	}
	if err := db.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(db.InitialPasswordPath())
	if err != nil {
		t.Fatal(err)
	}
	cfg.BasePath = prefix
	s, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	return s, db, strings.TrimSpace(string(data))
}

func initialSignIn(t *testing.T, s *Server, password string, required bool) (*http.Cookie, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	w := request(s, "POST", s.cfg.BasePath+"/api/auth/login", string(body), nil, "", s.cfg.PublicURL)
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var result struct {
		CSRF     string `json:"csrf_token"`
		Required bool   `json:"password_setup_required"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Required != required {
		t.Fatal("incorrect password setup flag")
	}
	if strings.Contains(w.Body.String(), password) {
		t.Fatal("login leaked password")
	}
	return w.Result().Cookies()[0], result.CSRF
}

func TestInitialPasswordBlocksPanelUntilSetupAndRevokesEverySession(t *testing.T) {
	s, db, password := initialPasswordFixture(t, "/ovpn")
	permanentPassword := strings.Repeat("🔐", 72)
	first, csrf := initialSignIn(t, s, password, true)
	second, _ := initialSignIn(t, s, password, true)
	for _, route := range []struct{ method, path string }{
		{"GET", "/dashboard"}, {"GET", "/clients"}, {"GET", "/certificates"}, {"GET", "/settings"}, {"GET", "/audit"}, {"GET", "/devices"}, {"GET", "/operations"}, {"GET", "/connections"}, {"GET", "/events"},
		{"GET", "/devices/x/profile"}, {"GET", "/devices/x/ccd"}, {"PUT", "/devices/x/ccd"}, {"PUT", "/settings/vpn"}, {"POST", "/pki/initialize"}, {"POST", "/clients"}, {"POST", "/clients/x/delete"}, {"POST", "/clients/x/devices"}, {"POST", "/devices/x/rotate"}, {"POST", "/devices/x/delete"}, {"POST", "/certificates/x/revoke"}, {"POST", "/operations/x/retry"}, {"POST", "/connections/disconnect"}, {"POST", "/auth/password"},
		{"POST", "/auth/totp/setup"}, {"POST", "/auth/totp/enable"}, {"POST", "/auth/totp/disable"},
	} {
		w := request(s, route.method, "/ovpn/api"+route.path, `{}`, first, csrf, s.cfg.PublicURL)
		if w.Code != 403 || !strings.Contains(w.Body.String(), `"code":"password_setup_required"`) {
			t.Fatalf("setup bypass %s %s: %d %s", route.method, route.path, w.Code, w.Body.String())
		}
	}
	w := request(s, "GET", "/ovpn/api/auth/session", "", first, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"password_setup_required":true`) {
		t.Fatal("session omitted setup requirement")
	}
	body := `{"new_password":"` + permanentPassword + `"}`
	w = request(s, "POST", "/ovpn/api/auth/setup-password", body, first, csrf, s.cfg.PublicURL)
	if w.Code != 200 {
		t.Fatalf("setup without current password failed: %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(db.InitialPasswordPath()); !os.IsNotExist(err) {
		t.Fatal("initial password file not removed")
	}
	for _, cookie := range []*http.Cookie{first, second} {
		if w := request(s, "GET", "/ovpn/api/auth/session", "", cookie, "", ""); w.Code != 401 {
			t.Fatal("setup did not revoke all sessions")
		}
	}
	var hash string
	var required bool
	if err := db.DB.QueryRow("SELECT password_hash,password_setup_required FROM admins").Scan(&hash, &required); err != nil || required || passwordhash.Verify(hash, permanentPassword) != nil {
		t.Fatal("permanent password not saved")
	}
	var count int
	if err := db.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='auth.password.setup'").Scan(&count); err != nil || count != 1 {
		t.Fatal("password setup was not audited")
	}
	if err := db.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, err := New(s.cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(s, "POST", "/ovpn/api/auth/login", `{"username":"admin","password":"`+password+`"}`, nil, "", s.cfg.PublicURL); w.Code != 401 {
		t.Fatal("initial password still works")
	}
	cookie, token := initialSignIn(t, s, permanentPassword, false)
	if w := request(s, "GET", "/ovpn/api/clients", "", cookie, "", ""); w.Code != 200 {
		t.Fatal("panel blocked after setup")
	}
	if w := request(s, "POST", "/ovpn/api/auth/setup-password", body, cookie, token, s.cfg.PublicURL); w.Code != 409 {
		t.Fatal("setup endpoint can overwrite a permanent password")
	}
}

func TestInitialPasswordLoginWithoutSetupSurvivesLogoutAndRestart(t *testing.T) {
	s, db, password := initialPasswordFixture(t, "")
	cookie, csrf := initialSignIn(t, s, password, true)
	if w := request(s, "POST", "/api/auth/logout", `{}`, cookie, csrf, s.cfg.PublicURL); w.Code != 200 {
		t.Fatal("pending user cannot log out")
	}
	if err := db.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(context.Background(), s.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	if err := reopened.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, err = New(s.cfg, reopened)
	if err != nil {
		t.Fatal(err)
	}
	initialSignIn(t, s, password, true)
	if data, err := os.ReadFile(reopened.InitialPasswordPath()); err != nil || strings.TrimSpace(string(data)) != password {
		t.Fatal("login consumed or changed the password")
	}
}

func TestInitialPasswordRejectsInvalidSetupAndRollsBackAuditFailure(t *testing.T) {
	s, db, password := initialPasswordFixture(t, "")
	cookie, csrf := initialSignIn(t, s, password, true)
	valid := `{"new_password":"` + newTestPassword + `"}`
	if w := request(s, "POST", "/api/auth/setup-password", valid, nil, "", s.cfg.PublicURL); w.Code != 401 {
		t.Fatal("unauthenticated setup allowed")
	}
	for _, tc := range []struct {
		body, csrf, origin string
		code               int
	}{
		{valid, "", s.cfg.PublicURL, 403}, {valid, csrf, "https://evil.test", 403}, {`{"new_password":"short"}`, csrf, s.cfg.PublicURL, 400}, {`{"new_password":"` + strings.Repeat("я", 73) + `"}`, csrf, s.cfg.PublicURL, 400},
		{`{"new_password":"` + password + `"}`, csrf, s.cfg.PublicURL, 400}, {`{"current_password":"anything","new_password":"` + newTestPassword + `"}`, csrf, s.cfg.PublicURL, 400},
	} {
		if w := request(s, "POST", "/api/auth/setup-password", tc.body, cookie, tc.csrf, tc.origin); w.Code != tc.code {
			t.Fatalf("setup rejected with %d, expected %d", w.Code, tc.code)
		}
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_setup BEFORE INSERT ON audit_events WHEN NEW.action='auth.password.setup' BEGIN SELECT RAISE(ABORT,'test'); END`); err != nil {
		t.Fatal(err)
	}
	if w := request(s, "POST", "/api/auth/setup-password", valid, cookie, csrf, s.cfg.PublicURL); w.Code != 500 {
		t.Fatalf("expected audit rollback, got %d", w.Code)
	}
	if err := db.Bootstrap(context.Background()); err != nil {
		t.Fatal("failed setup changed the initial password", err)
	}
	if w := request(s, "GET", "/api/auth/session", "", cookie, "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"password_setup_required":true`) {
		t.Fatal("failed setup changed session or requirement")
	}
	initialSignIn(t, s, password, true)
}

func TestInitialPasswordCleanupFailureDoesNotUndoCommittedPassword(t *testing.T) {
	s, db, password := initialPasswordFixture(t, "")
	cookie, csrf := initialSignIn(t, s, password, true)
	// A nonempty directory simulates a filesystem failure even when tests run as root.
	if err := os.Remove(db.InitialPasswordPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(db.InitialPasswordPath(), 0700); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(db.InitialPasswordPath(), "blocker")
	if err := os.WriteFile(blocker, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	w := request(s, "POST", "/api/auth/setup-password", `{"new_password":"`+newTestPassword+`"}`, cookie, csrf, s.cfg.PublicURL)
	if w.Code != 200 {
		t.Fatalf("cleanup failure undid successful setup: %d", w.Code)
	}
	initialSignIn(t, s, newTestPassword, false)
	if err := db.CleanupInitialPassword(context.Background()); err == nil {
		t.Fatal("filesystem error was hidden")
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := db.CleanupInitialPassword(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(db.InitialPasswordPath()); !os.IsNotExist(err) {
		t.Fatal("cleanup retry did not remove the file")
	}
}

func TestLoginBootstrapTracksInitialPasswordFile(t *testing.T) {
	for _, prefix := range []string{"", "/ovpn"} {
		t.Run(prefix, func(t *testing.T) {
			s, db, password := initialPasswordFixture(t, prefix)
			check := func(want bool) {
				t.Helper()
				w := request(s, "GET", prefix+"/api/auth/bootstrap", "", nil, "", "")
				var result map[string]any
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || len(result) != 1 || result["initial_password_available"] != want {
					t.Fatal("incorrect public bootstrap status", w.Code, w.Body.String())
				}
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("bootstrap status can be cached")
				}
				if strings.Contains(w.Body.String(), password) || strings.Contains(w.Body.String(), db.InitialPasswordPath()) {
					t.Fatal("bootstrap endpoint exposes private data")
				}
			}
			check(true)
			if prefix != "" && request(s, "GET", "/api/auth/bootstrap", "", nil, "", "").Code != 404 {
				t.Fatal("bootstrap endpoint bypassed base path")
			}
			cookie, csrf := initialSignIn(t, s, password, true)
			check(true) // Signing in alone does not consume the one-time password.
			path := db.InitialPasswordPath()
			if err := os.Rename(path, path+".saved"); err != nil {
				t.Fatal(err)
			}
			check(false) // The file is the source of the hint, even while DB setup is pending.
			if err := os.Rename(path+".saved", path); err != nil {
				t.Fatal(err)
			}
			check(true)
			w := request(s, "POST", prefix+"/api/auth/setup-password", `{"new_password":"`+newTestPassword+`"}`, cookie, csrf, s.cfg.PublicURL)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			check(false) // No restart or new backend instance is needed after setup.
		})
	}
}
