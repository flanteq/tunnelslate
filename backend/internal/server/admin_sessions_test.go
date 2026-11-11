package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"tunnelslate/internal/config"
)

func TestLoginAddressTrustBoundary(t *testing.T) {
	s := &Server{cfg: config.Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/64")}}}
	for _, tc := range []struct{ peer, xff, real, want string }{
		{"198.51.100.1:123", "203.0.113.99", "203.0.113.98", "198.51.100.1"},
		{"192.0.2.10:123", "203.0.113.99, 198.51.100.1", "", "198.51.100.1"},
		{"192.0.2.10:123", "198.51.100.1, 192.0.2.20", "", "198.51.100.1"},
		{"192.0.2.10:123", "bad", "198.51.100.1", "192.0.2.10"},
		{"192.0.2.10:123", "", "198.51.100.1", "198.51.100.1"},
		{"192.0.2.10:123", "", "bad", "192.0.2.10"},
		{"[2001:db8::1]:123", "2001:db8:1::2", "", "2001:db8:1::2"},
		{"[::ffff:198.51.100.1]:123", "203.0.113.99", "", "198.51.100.1"},
		{"192.0.2.10:123", "fe80::1%eth0", "", "192.0.2.10"},
		{"192.0.2.10:123", strings.Repeat("a", 4097), "", "192.0.2.10"},
	} {
		r := httptest.NewRequest("POST", "/api/auth/login", nil)
		r.RemoteAddr = tc.peer
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		r.Header.Set("X-Real-IP", tc.real)
		if got := s.loginAddress(r); got != tc.want {
			t.Errorf("%+v: got %s", tc, got)
		}
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "192.0.2.10:123"
	r.Header.Add("X-Forwarded-For", "203.0.113.99")
	r.Header.Add("X-Forwarded-For", "198.51.100.1")
	if got := s.loginAddress(r); got != "198.51.100.1" {
		t.Fatal("multiple header bypass", got)
	}
}

func TestAdministratorSessionDetailsAndTermination(t *testing.T) {
	h, db, cfg := fixture(t)
	s := h.(*Server)
	s.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")}
	r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"admin","password":"correct-password-123"}`))
	r.RemoteAddr = "192.0.2.10:123"
	r.Header.Set("Origin", cfg.PublicURL)
	r.Header.Set("X-Forwarded-For", "203.0.113.99, 198.51.100.1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("login: %d", w.Code)
	}
	root := w.Result().Cookies()[0]
	var login struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	csrf := login.CSRF
	second, _ := signIn(t, h)
	if _, err := db.DB.Exec(`INSERT INTO admins(username,password_hash,created_at) SELECT 'operator',password_hash,created_at FROM admins WHERE id=1;
 INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) VALUES ('legacy',2,'legacy-csrf',9999999999);
 INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) VALUES ('expired',1,'expired-csrf',1)`); err != nil {
		t.Fatal(err)
	}
	other, _ := loginAdmin(t, h, "operator", "correct-password-123")
	// Login itself cleans expired sessions. Add one afterwards to check that
	// listing filters it before the background cleanup has run.
	if _, err := db.DB.Exec("INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) VALUES ('expired-list',1,'expired-csrf',1)"); err != nil {
		t.Fatal(err)
	}
	w = request(h, "GET", "/api/admins", "", root, "", "")
	var accounts []adminAccount
	if err := json.Unmarshal(w.Body.Bytes(), &accounts); err != nil || w.Code != 200 || len(accounts) != 2 {
		t.Fatal("session list", w.Code, err)
	}
	if accounts[0].Sessions != 2 || len(accounts[0].SessionDetails) != 2 || accounts[1].Sessions != 2 {
		t.Fatal("wrong session counts", accounts)
	}
	currentCount, legacyCount := 0, 0
	for _, a := range accounts {
		for _, p := range a.SessionDetails {
			if p.Current {
				currentCount++
				if p.IPAddress != "198.51.100.1" || p.CreatedAt == 0 || p.ExpiresAt <= p.CreatedAt {
					t.Fatal("wrong login metadata", p)
				}
			}
			if p.CreatedAt == 0 && p.IPAddress == "" {
				legacyCount++
			}
		}
	}
	if currentCount != 1 || legacyCount != 1 {
		t.Fatal("current or legacy metadata", currentCount, legacyCount)
	}
	for _, secret := range []string{root.Value, tokenHash(root.Value), csrf, "legacy-csrf"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("session secret leaked")
		}
	}
	path := "/api/admins/2/end-sessions"
	for _, tc := range []struct {
		cookie       *http.Cookie
		csrf, origin string
		code         int
	}{
		{nil, "", cfg.PublicURL, 401}, {root, "", cfg.PublicURL, 403}, {root, csrf, "https://evil.test", 403},
	} {
		if got := request(h, "POST", path, "{}", tc.cookie, tc.csrf, tc.origin).Code; got != tc.code {
			t.Fatal("termination guard", got)
		}
	}
	if request(h, "POST", "/api/admins/999/end-sessions", "{}", root, csrf, cfg.PublicURL).Code != 404 {
		t.Fatal("missing account guard")
	}
	rootReader, otherReader := s.events.subscribe(tokenHash(root.Value)), s.events.subscribe(tokenHash(other.Value))
	defer s.events.unsubscribe(rootReader)
	defer s.events.unsubscribe(otherReader)
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_session_audit BEFORE INSERT ON audit_events WHEN NEW.action='admin.sessions.end' BEGIN SELECT RAISE(FAIL,'test'); END`); err != nil {
		t.Fatal(err)
	}
	if request(h, "POST", path, "{}", root, csrf, cfg.PublicURL).Code != 500 {
		t.Fatal("audit failure accepted")
	}
	if len(otherReader.revoked) != 0 || request(h, "GET", "/api/auth/session", "", other, "", "").Code != 200 {
		t.Fatal("audit rollback lost session")
	}
	db.DB.Exec("DROP TRIGGER fail_session_audit")
	w = request(h, "POST", path, "{}", root, csrf, cfg.PublicURL)
	if w.Code != 200 || strings.Contains(w.Body.String(), `"signed_out":true`) {
		t.Fatal("termination", w.Code)
	}
	if len(otherReader.revoked) != 1 || len(rootReader.revoked) != 0 {
		t.Fatal("SSE revocation isolation")
	}
	if request(h, "GET", "/api/auth/session", "", other, "", "").Code != 401 || request(h, "GET", "/api/auth/session", "", root, "", "").Code != 200 {
		t.Fatal("session termination isolation")
	}
	freshOther, _ := loginAdmin(t, h, "operator", "correct-password-123") // Password remains valid.
	var count int
	if err := db.DB.QueryRow("SELECT count(*) FROM audit_events WHERE actor='admin' AND action='admin.sessions.end' AND target='operator'").Scan(&count); err != nil || count != 1 {
		t.Fatal("missing termination audit", err)
	}
	before := s.events.snapshot()["admins"]
	if _, err := db.DB.Exec("INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) VALUES ('expired-cleanup',1,'expired-csrf',1)"); err != nil {
		t.Fatal(err)
	}
	if err := s.expireAdminSessions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.events.snapshot()["admins"] <= before {
		t.Fatal("expiry did not invalidate count")
	}
	w = request(h, "POST", "/api/admins/1/end-sessions", "{}", root, csrf, cfg.PublicURL)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"signed_out":true`) || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("own session termination", w.Code)
	}
	for _, cookie := range []*http.Cookie{root, second} {
		if request(h, "GET", "/api/auth/session", "", cookie, "", "").Code != 401 {
			t.Fatal("own session survived")
		}
	}
	if len(rootReader.revoked) != 1 {
		t.Fatal("own stream survived")
	}
	if request(h, "GET", "/api/auth/session", "", freshOther, "", "").Code != 200 {
		t.Fatal("self termination logged out another account")
	}
}
