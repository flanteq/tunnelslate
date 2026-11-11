package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"tunnelslate/internal/passwordhash"

	"golang.org/x/crypto/bcrypt"
	"tunnelslate/internal/store"
)

const newTestPassword = "new-administrator-password-456"

func passwordBody(current, next string) string {
	data, _ := json.Marshal(map[string]string{"current_password": current, "new_password": next})
	return string(data)
}

func TestPasswordChangeRevokesSessionsAndSurvivesRestart(t *testing.T) {
	_, db, cfg := fixture(t)
	cfg.BasePath = "/ovpn"
	h, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	login := func(handler http.Handler, password string) *http.Cookie {
		data, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
		w := request(handler, "POST", "/ovpn/api/auth/login", string(data), nil, "", cfg.PublicURL)
		if w.Code != 200 {
			t.Fatalf("login code=%d", w.Code)
		}
		return w.Result().Cookies()[0]
	}
	first, second := login(h, "correct-password-123"), login(h, "correct-password-123")
	var csrf string
	if err := db.DB.QueryRow("SELECT csrf_token FROM sessions WHERE token_hash=?", tokenHash(first.Value)).Scan(&csrf); err != nil {
		t.Fatal(err)
	}
	w := request(h, "POST", "/ovpn/api/auth/password", passwordBody("correct-password-123", newTestPassword), first, csrf, cfg.PublicURL)
	if w.Code != 200 {
		t.Fatalf("change password: code=%d", w.Code)
	}
	if len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Path != "/ovpn/" || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("session cookie not cleared at base path")
	}
	for _, cookie := range []*http.Cookie{first, second} {
		if w := request(h, "GET", "/ovpn/api/auth/session", "", cookie, "", ""); w.Code != 401 {
			t.Fatal("old session survived password change")
		}
	}
	var saved string
	if err := db.DB.QueryRow("SELECT password_hash FROM admins WHERE id=1").Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if saved == newTestPassword || passwordhash.Verify(saved, newTestPassword) != nil || passwordhash.Verify(saved, "correct-password-123") == nil {
		t.Fatal("password hash not updated correctly")
	}
	var events int
	if err := db.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='auth.password.change'").Scan(&events); err != nil || events != 1 {
		t.Fatalf("audit count=%d err=%v", events, err)
	}
	if strings.Contains(w.Body.String(), newTestPassword) || strings.Contains(w.Body.String(), saved) {
		t.Fatal("secret in password change response")
	}
	oldLogin := request(h, "POST", "/ovpn/api/auth/login", `{"username":"admin","password":"correct-password-123"}`, nil, "", cfg.PublicURL)
	if oldLogin.Code != 401 {
		t.Fatal("old password still accepted")
	}
	// Reopen the actual SQLite file and repeat bootstrap without changing credentials.
	if err := db.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(context.Background(), cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.DB.Close() })
	if err := reopened.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(cfg, reopened)
	if err != nil {
		t.Fatal(err)
	}
	login(restarted, newTestPassword)
	if w := request(restarted, "POST", "/ovpn/api/auth/login", `{"username":"admin","password":"correct-password-123"}`, nil, "", cfg.PublicURL); w.Code != 401 {
		t.Fatal("restart restored bootstrap password")
	}
	if err := reopened.Bootstrap(context.Background()); err != nil {
		t.Fatal("existing database still requires bootstrap password:", err)
	}
}

func TestPasswordChangeRejectsUnauthorizedAndInvalidRequests(t *testing.T) {
	h, db, cfg := fixture(t)
	body := passwordBody("correct-password-123", newTestPassword)
	if w := request(h, "POST", "/api/auth/password", body, nil, "", cfg.PublicURL); w.Code != 401 {
		t.Fatal(w.Code)
	}
	cookie, csrf := signIn(t, h)
	for _, tc := range []struct {
		body, csrf, origin string
		code               int
	}{
		{body, "", cfg.PublicURL, 403},
		{body, csrf, "https://evil.test", 403},
		{passwordBody("wrong-password", newTestPassword), csrf, cfg.PublicURL, 403},
		{passwordBody("correct-password-123", "short"), csrf, cfg.PublicURL, 400},
		{passwordBody("correct-password-123", strings.Repeat("я", 11)), csrf, cfg.PublicURL, 400},
		{passwordBody("correct-password-123", strings.Repeat("я", 73)), csrf, cfg.PublicURL, 400},
		{passwordBody("correct-password-123", "correct-password-123"), csrf, cfg.PublicURL, 400},
		{`{"current_password":"correct-password-123","new_password":"new-password-123","reset":true}`, csrf, cfg.PublicURL, 400},
	} {
		if w := request(h, "POST", "/api/auth/password", tc.body, cookie, tc.csrf, tc.origin); w.Code != tc.code {
			t.Fatalf("expected HTTP %d, got %d", tc.code, w.Code)
		}
	}
	if w := request(h, "GET", "/api/auth/session", "", cookie, "", ""); w.Code != 200 {
		t.Fatal("failed password changes invalidated session")
	}
	var events int
	if err := db.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='auth.password.change'").Scan(&events); err != nil || events != 0 {
		t.Fatal("failed change recorded as success")
	}
}

func TestPasswordChangeAndLoginSupportSeventyTwoUnicodeCharacters(t *testing.T) {
	h, _, cfg := fixture(t)
	cookie, csrf := signIn(t, h)
	previous := "correct-password-123"
	for _, next := range []string{strings.Repeat("я", 72), strings.Repeat("🔐", 72)} {
		w := request(h, "POST", "/api/auth/password", passwordBody(previous, next), cookie, csrf, cfg.PublicURL)
		if w.Code != 200 {
			t.Fatalf("unicode password change: %d %s", w.Code, w.Body.String())
		}
		body, err := json.Marshal(map[string]string{"username": "admin", "password": next})
		if err != nil {
			t.Fatal(err)
		}
		w = request(h, "POST", "/api/auth/login", string(body), nil, "", cfg.PublicURL)
		if w.Code != 200 {
			t.Fatalf("unicode login: %d", w.Code)
		}
		cookie = w.Result().Cookies()[0]
		var result struct {
			CSRF string `json:"csrf_token"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		csrf = result.CSRF
		previous = next
	}
}

func TestPasswordChangeRollsBackIfAuditFails(t *testing.T) {
	h, db, cfg := fixture(t)
	cookie, csrf := signIn(t, h)
	_, err := db.DB.Exec(`CREATE TRIGGER fail_password_audit BEFORE INSERT ON audit_events
	 WHEN NEW.action='auth.password.change' BEGIN SELECT RAISE(FAIL,'simulated audit failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	w := request(h, "POST", "/api/auth/password", passwordBody("correct-password-123", newTestPassword), cookie, csrf, cfg.PublicURL)
	if w.Code != 500 {
		t.Fatal(w.Code)
	}
	if w := request(h, "GET", "/api/auth/session", "", cookie, "", ""); w.Code != 200 {
		t.Fatal("failed transaction revoked sessions")
	}
	var hash string
	if err := db.DB.QueryRow("SELECT password_hash FROM admins WHERE id=1").Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte("correct-password-123")) != nil {
		t.Fatal("failed transaction changed password")
	}
}

func TestPasswordChangeAttemptLimit(t *testing.T) {
	h, _, cfg := fixture(t)
	cookie, csrf := signIn(t, h)
	for i := 0; i < 5; i++ {
		if w := request(h, "POST", "/api/auth/password", passwordBody("wrong-password", newTestPassword), cookie, csrf, cfg.PublicURL); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	w := request(h, "POST", "/api/auth/password", passwordBody("wrong-password", newTestPassword), cookie, csrf, cfg.PublicURL)
	if w.Code != 429 || w.Header().Get("Retry-After") != "300" {
		t.Fatal("password change rate limit missing")
	}
}
