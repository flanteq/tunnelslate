package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"tunnelslate/internal/store"
)

func loginFrom(s *Server, ip, forwarded, password string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"admin","password":"`+password+`"}`))
	r.RemoteAddr = ip
	if forwarded != "" {
		r.Header.Set("X-Forwarded-For", forwarded)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func directLoginFailure(s *Server, ip string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/auth/login", nil)
	r.RemoteAddr = ip
	w := httptest.NewRecorder()
	s.rejectLogin(w, r)
	return w
}

func TestLoginIPBanPersistsWithoutExtendingOrEndingSessions(t *testing.T) {
	h, db, cfg := fixture(t)
	s := h.(*Server)
	now := time.Now().Truncate(time.Second)
	s.loginClock = func() time.Time { return now }
	cookie, _ := signIn(t, s)
	for i := 0; i < 4; i++ {
		if w := loginFrom(s, "127.0.0.1:1", "", "wrong"); w.Code != 401 {
			t.Fatal(i, w.Code)
		}
	}
	// Successful sign-ins neither count as failures nor erase earlier failures.
	if w := loginFrom(s, "127.0.0.1:2", "", "correct-password-123"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	w := request(s, "POST", "/api/auth/login", `{"username":"missing-account","password":"wrong"}`, nil, "", "")
	if w.Code != 429 || w.Header().Get("Retry-After") != "900" || !strings.Contains(w.Body.String(), "auth.ip_blocked") {
		t.Fatal(w.Code, w.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["params"].(map[string]any)["retry_after"] != float64(900) {
		t.Fatal(response)
	}
	until := now.Add(loginBanDuration).Unix()
	if response["params"].(map[string]any)["retry_at"] != float64(until) {
		t.Fatal(response)
	}

	reopened, err := store.Open(context.Background(), cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	restarted, err := New(cfg, reopened)
	if err != nil {
		t.Fatal(err)
	}
	restarted.loginClock = s.loginClock
	now = now.Add(2 * time.Minute)
	for i := 0; i < 3; i++ {
		w = loginFrom(restarted, "127.0.0.1:4", "203.0.113.100", "correct-password-123")
		if w.Code != 429 || w.Header().Get("Retry-After") != "780" {
			t.Fatal("ban reset, extended or spoofed", w.Code, w.Body.String())
		}
	}
	if w := request(restarted, "POST", "/api/auth/totp", `{}`, nil, "", ""); w.Code != 429 || !strings.Contains(w.Body.String(), "auth.ip_blocked") {
		t.Fatal("second-factor bypass", w.Code)
	}
	if w := request(restarted, "GET", "/api/auth/session", "", cookie, "", ""); w.Code != 200 {
		t.Fatal("active session blocked", w.Code)
	}
	if w := loginFrom(restarted, "198.51.100.7:1", "", "correct-password-123"); w.Code != 200 {
		t.Fatal("another IP blocked", w.Code)
	}
	var auditCount int
	if err := db.DB.QueryRow(`SELECT count(*) FROM audit_events WHERE action='auth.ip_blocked' AND actor='system' AND target='127.0.0.1' AND severity='WARNING'`).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatal("duplicate/missing ban audit", auditCount, err)
	}
	now = time.Unix(until, 0)
	if w := loginFrom(restarted, "127.0.0.1:1", "", "correct-password-123"); w.Code != 200 {
		t.Fatal("ban did not expire", w.Code)
	}
	if w := loginFrom(restarted, "127.0.0.1:1", "", "wrong"); w.Code != 401 {
		t.Fatal("failures not reset", w.Code)
	}
	now = now.Add(loginFailureWindow)
	if err := restarted.expireAdminSessions(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"login_ip_failures", "login_ip_bans"} {
		var count int
		if err := db.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatal("expired state retained", table, count, err)
		}
	}
}

func TestLoginIPFailureWindowSlides(t *testing.T) {
	h, _, _ := fixture(t)
	s := h.(*Server)
	start := time.Now().Truncate(time.Second)
	now := start
	s.loginClock = func() time.Time { return now }
	for i := 0; i < 4; i++ {
		now = start.Add(time.Duration(i) * time.Minute)
		if w := directLoginFailure(s, "192.0.2.1:1"); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	restarted, err := New(s.cfg, s.store)
	if err != nil {
		t.Fatal(err)
	}
	restarted.loginClock = s.loginClock
	s = restarted
	now = start.Add(15 * time.Minute)
	if w := directLoginFailure(s, "192.0.2.1:1"); w.Code != 401 {
		t.Fatal("old failure counted at window boundary", w.Code)
	}
	now = now.Add(time.Second)
	if w := directLoginFailure(s, "192.0.2.1:1"); w.Code != 429 {
		t.Fatal("window incorrectly reset", w.Code)
	}
}

func TestLoginIPConcurrentFailuresAndSessionRace(t *testing.T) {
	h, db, _ := fixture(t)
	s := h.(*Server)
	var wg sync.WaitGroup
	codes := make(chan int, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- directLoginFailure(s, "127.0.0.1:1").Code }()
	}
	wg.Wait()
	close(codes)
	failed := 0
	for code := range codes {
		if code == 401 {
			failed++
		} else if code != 429 {
			t.Fatal(code)
		}
	}
	if failed != 4 {
		t.Fatal("concurrent threshold", failed)
	}
	var count int
	if err := db.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='auth.ip_blocked'").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	// A password verified before the ban must not create a session afterwards.
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	r := httptest.NewRequest("POST", "/api/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:1"
	_, err = s.newLoginSession(r, tx, loginIdentity{})
	w := httptest.NewRecorder()
	if !s.respondLoginBan(w, err) || w.Code != 429 {
		t.Fatal("in-flight login bypassed ban", err)
	}
}

func TestLoginIPTrustedProxyAndRequestBudget(t *testing.T) {
	h, db, _ := fixture(t)
	s := h.(*Server)
	s.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")}
	for i := 0; i < 5; i++ {
		w := loginFrom(s, "192.0.2.10:1", "203.0.113.9, 198.51.100.1", "wrong")
		want := 401
		if i == 4 {
			want = 429
		}
		if w.Code != want {
			t.Fatal(w.Code)
		}
	}
	// An untrusted hop in XFF cannot move the limit to an attacker-supplied IP.
	if w := loginFrom(s, "192.0.2.10:2", "203.0.113.100, 198.51.100.1", "correct-password-123"); w.Code != 429 {
		t.Fatal("forwarded IP spoofed", w.Code)
	}
	if w := loginFrom(s, "192.0.2.10:2", "198.51.100.2", "correct-password-123"); w.Code != 200 {
		t.Fatal("proxy-wide ban", w.Code)
	}
	var ip string
	if err := db.DB.QueryRow("SELECT ip FROM login_ip_bans").Scan(&ip); err != nil || ip != "198.51.100.1" {
		t.Fatal(ip, err)
	}
	r := httptest.NewRequest("POST", "/api/auth/login", nil)
	r.RemoteAddr = "[::ffff:198.51.100.1]:2"
	if err := s.loginBan(r, db.DB); err == nil {
		t.Fatal("IPv4-mapped IPv6 bypass")
	}
	// Malformed requests consume the cheap request budget, not the failure ban.
	for i := 0; i < 61; i++ {
		r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{`))
		r.RemoteAddr = "198.51.100.3:1"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		want := 400
		if i == 60 {
			want = 429
		}
		if w.Code != want {
			t.Fatal(i, w.Code)
		}
	}
}

func TestLoginIPAuditFailureRollsBackBan(t *testing.T) {
	h, db, _ := fixture(t)
	s := h.(*Server)
	for i := 0; i < 4; i++ {
		if w := directLoginFailure(s, "127.0.0.1:1"); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_ip_ban_audit BEFORE INSERT ON audit_events WHEN NEW.action='auth.ip_blocked' BEGIN SELECT RAISE(ABORT,'test'); END`); err != nil {
		t.Fatal(err)
	}
	if w := directLoginFailure(s, "127.0.0.1:1"); w.Code != 500 {
		t.Fatal("audit failure ignored", w.Code)
	}
	var count int
	db.DB.QueryRow("SELECT count(*) FROM login_ip_bans").Scan(&count)
	if count != 0 {
		t.Fatal("partial ban committed")
	}
	db.DB.Exec("DROP TRIGGER fail_ip_ban_audit")
	if w := directLoginFailure(s, "127.0.0.1:1"); w.Code != 429 {
		t.Fatal("fifth failure lost", w.Code)
	}
}

func TestLoginIPCombinesPasswordAndTOTPFailures(t *testing.T) {
	s, _, clock := totpFixture(t, true)
	challenge := totpChallenge(t, s, "correct-password-123")
	for i := 0; i < 2; i++ {
		if w := loginFrom(s, "127.0.0.1:1", "", "wrong"); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	for i := 0; i < 3; i++ {
		want := 401
		if i == 2 {
			want = 429
		}
		if w := totpPOST(t, s, "totp", map[string]string{"challenge_token": challenge, "code": "bad"}, nil, ""); w.Code != want {
			t.Fatal(i, w.Code)
		}
	}
	code := totpCodeAt(t, testTOTPSecret, *clock)
	if w := totpPOST(t, s, "totp", map[string]string{"challenge_token": challenge, "code": code}, nil, ""); w.Code != 429 || !strings.Contains(w.Body.String(), "auth.ip_blocked") {
		t.Fatal("valid challenge bypassed IP ban", w.Code)
	}
	// Three bad codes have not reached the separate per-account limit. A user
	// who has the password challenge and the valid code can use another IP.
	body, _ := json.Marshal(map[string]string{"challenge_token": challenge, "code": code})
	r := httptest.NewRequest("POST", "/api/auth/totp", strings.NewReader(string(body)))
	r.RemoteAddr = "198.51.100.10:1"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("IP ban became account-wide", w.Code, w.Body.String())
	}
}
