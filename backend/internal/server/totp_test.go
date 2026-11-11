package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"tunnelslate/internal/store"
)

const testTOTPSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestTOTPProvisioningURIWorksWithPortsIPv6AndSubpaths(t *testing.T) {
	for _, origin := range []string{"https://desk.example.com", "https://desk.example.com:8443", "https://[2001:db8::1]:8443"} {
		s := &Server{}
		s.cfg.PublicURL = origin
		s.cfg.BasePath = "/tools/ovpn"
		key, err := s.newTOTPKey("owner")
		if err != nil {
			t.Fatal(err)
		}
		uri, err := url.Parse(key.URL())
		if err != nil {
			t.Fatal(err)
		}
		// A label is issuer:account, with no extra ':' in the account itself.
		if strings.Count(uri.Path, ":") != 1 || strings.Count(strings.TrimPrefix(uri.Path, "/"), "/") != 0 {
			t.Fatal("reserved separators in provisioning label")
		}
		query := uri.Query()
		if uri.Scheme != "otpauth" || uri.Host != "totp" || query.Get("issuer") != "TunnelSlate" || query.Get("digits") != "6" || query.Get("period") != "30" || query.Get("algorithm") != "SHA1" {
			t.Fatal("incorrect provisioning settings")
		}
		parsed, err := otp.NewKeyFromURL(key.URL())
		if err != nil || parsed.AccountName() != key.AccountName() || parsed.Secret() != key.Secret() {
			t.Fatal("provisioning URI did not round-trip", err)
		}
	}
}

func totpFixture(t *testing.T, enabled bool) (*Server, *store.Store, *time.Time) {
	t.Helper()
	h, db, _ := fixture(t)
	s := h.(*Server)
	now := time.Now().Truncate(time.Second)
	s.totpClock = func() time.Time { return now }
	s.loginClock = s.totpClock
	if enabled {
		seedTOTP(t, db)
	}
	return s, db, &now
}
func seedTOTP(t *testing.T, db *store.Store) {
	t.Helper()
	sealed, err := db.SealTOTPSecret(context.Background(), 1, testTOTPSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("INSERT INTO admin_totp(admin_id,secret,generation) VALUES (1,?,'test-generation')", sealed); err != nil {
		t.Fatal(err)
	}
}
func totpCodeAt(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	return code
}
func totpPOST(t *testing.T, s *Server, path string, body any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return request(s, "POST", s.cfg.BasePath+"/api/auth/"+path, string(encoded), cookie, csrf, s.cfg.PublicURL)
}
func totpChallenge(t *testing.T, s *Server, password string) string {
	t.Helper()
	w := totpPOST(t, s, "login", map[string]string{"username": "admin", "password": password}, nil, "")
	var result struct {
		Required bool   `json:"totp_required"`
		Token    string `json:"challenge_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 202 || !result.Required || len(result.Token) != 64 || len(w.Result().Cookies()) != 0 {
		t.Fatal("password step granted access or omitted its challenge", w.Code)
	}
	return result.Token
}

func TestTOTPMatchesRFC6238AndRejectsReplayAndWideSkew(t *testing.T) {
	for _, tc := range []struct {
		unix int64
		code string
	}{
		{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"},
	} {
		step, valid := matchTOTPStep(testTOTPSecret, tc.code, time.Unix(tc.unix, 0), -1)
		if !valid || step != tc.unix/30 {
			t.Fatal("RFC vector mismatch", tc.unix)
		}
		if _, valid := matchTOTPStep(testTOTPSecret, tc.code, time.Unix(tc.unix, 0), step); valid {
			t.Fatal("used code accepted")
		}
	}
	for _, unix := range []int64{29, 59, 89} {
		if _, valid := matchTOTPStep(testTOTPSecret, "287082", time.Unix(unix, 0), -1); !valid {
			t.Fatal("one-step skew rejected", unix)
		}
	}
	for _, code := range []string{"28708", "２８７０８２", "2870820", "not-a-code"} {
		if _, valid := matchTOTPStep(testTOTPSecret, code, time.Unix(59, 0), -1); valid {
			t.Fatal("invalid code accepted")
		}
	}
	if _, valid := matchTOTPStep(testTOTPSecret, "287082", time.Unix(119, 0), -1); valid {
		t.Fatal("wide clock skew accepted")
	}
}

func TestTOTPSetupLoginAndDisableLifecycle(t *testing.T) {
	s, db, clock := totpFixture(t, false)
	owner, csrf := signIn(t, s)
	second, _ := signIn(t, s)
	if _, err := db.DB.Exec("INSERT INTO admins(username,password_hash,created_at) SELECT 'other',password_hash,created_at FROM admins WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	other, _ := loginAdmin(t, s, "other", "correct-password-123")
	if w := totpPOST(t, s, "totp/setup", map[string]string{"current_password": "wrong-password"}, owner, csrf); w.Code != 403 {
		t.Fatal("setup accepted incorrect password")
	}
	w := totpPOST(t, s, "totp/setup", map[string]string{"current_password": "correct-password-123"}, owner, csrf)
	var setup struct {
		Token  string `json:"setup_token"`
		Secret string `json:"secret"`
		QR     string `json:"qr_code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &setup); err != nil || w.Code != 200 || len(setup.Token) != 64 || setup.Secret == "" {
		t.Fatal("setup missing", w.Code)
	}
	qr, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(setup.QR, "data:image/png;base64,"))
	if err != nil || !strings.HasPrefix(string(qr), "\x89PNG\r\n\x1a\n") {
		t.Fatal("QR is not a PNG")
	}
	var enabled int
	db.DB.QueryRow("SELECT count(*) FROM admin_totp").Scan(&enabled)
	if enabled != 0 {
		t.Fatal("setup enabled TOTP before verification")
	}
	if w := totpPOST(t, s, "totp/enable", map[string]string{"setup_token": setup.Token, "code": "bad"}, owner, csrf); w.Code != 400 {
		t.Fatal("invalid setup code accepted", w.Code)
	}
	secondSession := request(s, "GET", "/api/auth/session", "", second, "", "")
	var sessionInfo struct {
		CSRF string `json:"csrf_token"`
	}
	json.Unmarshal(secondSession.Body.Bytes(), &sessionInfo)
	if w := totpPOST(t, s, "totp/enable", map[string]string{"setup_token": setup.Token, "code": totpCodeAt(t, setup.Secret, *clock)}, second, sessionInfo.CSRF); w.Code != 409 {
		t.Fatal("setup not bound to originating session")
	}
	if w := totpPOST(t, s, "totp/enable", map[string]string{"setup_token": setup.Token, "code": totpCodeAt(t, setup.Secret, *clock)}, owner, csrf); w.Code != 200 {
		t.Fatal("TOTP enable failed", w.Code)
	}
	if request(s, "GET", "/api/auth/session", "", second, "", "").Code != 401 {
		t.Fatal("old session survived TOTP enable")
	}
	for _, cookie := range []*http.Cookie{owner, other} {
		if request(s, "GET", "/api/auth/session", "", cookie, "", "").Code != 200 {
			t.Fatal("current or unrelated session ended")
		}
	}
	list := request(s, "GET", "/api/admins", "", owner, "", "")
	var accounts []adminAccount
	if err := json.Unmarshal(list.Body.Bytes(), &accounts); err != nil || !accounts[0].TOTPEnabled || strings.Contains(list.Body.String(), setup.Secret) || strings.Contains(list.Body.String(), setup.Token) {
		t.Fatal("TOTP state missing or credentials leaked")
	}
	challenge := totpChallenge(t, s, "correct-password-123")
	if w := totpPOST(t, s, "totp", map[string]string{"challenge_token": challenge, "code": totpCodeAt(t, setup.Secret, *clock)}, nil, ""); w.Code != 401 {
		t.Fatal("setup code reused to sign in")
	}
	*clock = clock.Add(30 * time.Second)
	w = totpPOST(t, s, "totp", map[string]string{"challenge_token": challenge, "code": totpCodeAt(t, setup.Secret, *clock)}, nil, "")
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatal("TOTP sign-in failed", w.Code)
	}
	verified := w.Result().Cookies()[0]
	if w := totpPOST(t, s, "totp", map[string]string{"challenge_token": challenge, "code": totpCodeAt(t, setup.Secret, *clock)}, nil, ""); w.Code != 401 {
		t.Fatal("challenge reused")
	}
	*clock = clock.Add(30 * time.Second)
	if w := totpPOST(t, s, "totp/disable", map[string]string{"current_password": "wrong-password", "code": totpCodeAt(t, setup.Secret, *clock)}, owner, csrf); w.Code != 403 {
		t.Fatal("disable accepted incorrect password")
	}
	if w := totpPOST(t, s, "totp/disable", map[string]string{"current_password": "correct-password-123", "code": "bad"}, owner, csrf); w.Code != 400 {
		t.Fatal("disable accepted incorrect code")
	}
	if w := totpPOST(t, s, "totp/disable", map[string]string{"current_password": "correct-password-123", "code": totpCodeAt(t, setup.Secret, *clock)}, owner, csrf); w.Code != 200 {
		t.Fatal("disable failed", w.Code)
	}
	if request(s, "GET", "/api/auth/session", "", verified, "", "").Code != 401 {
		t.Fatal("other session survived TOTP disable")
	}
	if request(s, "GET", "/api/auth/session", "", owner, "", "").Code != 200 {
		t.Fatal("disable ended current session")
	}
	w = totpPOST(t, s, "login", map[string]string{"username": "admin", "password": "correct-password-123"}, nil, "")
	if w.Code != 200 {
		t.Fatal("password-only login not restored", w.Code)
	}
	var audits int
	db.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action IN ('auth.totp.enabled','auth.totp.disabled')").Scan(&audits)
	if audits != 2 {
		t.Fatal("TOTP changes not audited")
	}
}

func TestTOTPLimitsPersistAcrossChallengesAndServerRestart(t *testing.T) {
	s, db, clock := totpFixture(t, true)
	challenge := totpChallenge(t, s, "correct-password-123")
	for i := 0; i < 5; i++ {
		want := 401
		if i == 4 {
			want = 429
		}
		if w := totpPOST(t, s, "totp", map[string]string{"challenge_token": challenge, "code": "bad"}, nil, ""); w.Code != want {
			t.Fatal("incorrect invalid-code response", w.Code)
		}
	}
	restarted, err := New(s.cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	restarted.totpClock = s.totpClock
	restarted.loginClock = s.loginClock
	if w := totpPOST(t, restarted, "totp", map[string]string{"challenge_token": challenge, "code": totpCodeAt(t, testTOTPSecret, *clock)}, nil, ""); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("restart reset per-account limit", w.Code)
	}
	if w := totpPOST(t, restarted, "login", map[string]string{"username": "admin", "password": "correct-password-123"}, nil, ""); w.Code != 429 {
		t.Fatal("new challenge bypassed account limit")
	}
	// Another IP still hits the independent per-account TOTP limit.
	otherIP := func(path string, body any) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/api/auth/"+path, strings.NewReader(string(data)))
		r.RemoteAddr = "198.51.100.55:1"
		w := httptest.NewRecorder()
		restarted.ServeHTTP(w, r)
		return w
	}
	if w := otherIP("totp", map[string]string{"challenge_token": challenge, "code": totpCodeAt(t, testTOTPSecret, *clock)}); w.Code != 429 || !strings.Contains(w.Body.String(), "auth.totp_rate_limit") {
		t.Fatal("account limit bypassed from another IP", w.Code, w.Body.String())
	}
	*clock = clock.Add(6 * time.Minute)
	if w := otherIP("login", map[string]string{"username": "admin", "password": "correct-password-123"}); w.Code != 202 {
		t.Fatal("account limit did not expire independently", w.Code)
	}
	if w := totpPOST(t, restarted, "login", map[string]string{"username": "admin", "password": "correct-password-123"}, nil, ""); w.Code != 429 || !strings.Contains(w.Body.String(), "auth.ip_blocked") {
		t.Fatal("account expiry cleared IP ban", w.Code)
	}
	*clock = clock.Add(10 * time.Minute)
	if w := totpPOST(t, restarted, "totp", map[string]string{"challenge_token": challenge, "code": totpCodeAt(t, testTOTPSecret, *clock)}, nil, ""); w.Code != 401 || !strings.Contains(w.Body.String(), "auth.totp_challenge_expired") {
		t.Fatal("expired challenge accepted")
	}
	challenge = totpChallenge(t, restarted, "correct-password-123")
	if w := totpPOST(t, restarted, "totp", map[string]string{"challenge_token": challenge, "code": totpCodeAt(t, testTOTPSecret, *clock)}, nil, ""); w.Code != 200 {
		t.Fatal("limit did not expire", w.Code)
	}
}

func TestTOTPChallengeAndCodeAreConsumedOnceUnderConcurrentRequests(t *testing.T) {
	s, _, clock := totpFixture(t, true)
	first := totpChallenge(t, s, "correct-password-123")
	second := totpChallenge(t, s, "correct-password-123")
	code := totpCodeAt(t, testTOTPSecret, *clock)
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for _, challenge := range []string{first, second} {
		wg.Add(1)
		go func(token string) {
			defer wg.Done()
			body, _ := json.Marshal(map[string]string{"challenge_token": token, "code": code})
			statuses <- request(s, "POST", "/api/auth/totp", string(body), nil, "", s.cfg.PublicURL).Code
		}(challenge)
	}
	wg.Wait()
	close(statuses)
	var successes, rejected int
	for status := range statuses {
		if status == 200 {
			successes++
		} else if status == 401 {
			rejected++
		} else {
			t.Fatal("unexpected concurrent response", status)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatal("TOTP code accepted more than once")
	}
}

func TestTOTPPasswordResetPreservesFactorAndInvalidatesOldChallenge(t *testing.T) {
	s, db, clock := totpFixture(t, true)
	old := totpChallenge(t, s, "correct-password-123")
	reset, err := db.RecoverAdmin(context.Background(), "admin", false)
	if err != nil {
		t.Fatal(err)
	}
	if w := totpPOST(t, s, "totp", map[string]string{"challenge_token": old, "code": totpCodeAt(t, testTOTPSecret, *clock)}, nil, ""); w.Code != 401 || !strings.Contains(w.Body.String(), "auth.totp_challenge_expired") {
		t.Fatal("password reset left old challenge valid")
	}
	challenge := totpChallenge(t, s, reset.TemporaryPassword)
	w := totpPOST(t, s, "totp", map[string]string{"challenge_token": challenge, "code": totpCodeAt(t, testTOTPSecret, *clock)}, nil, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"password_setup_required":true`) {
		t.Fatal("temporary password bypassed TOTP or setup")
	}
	if w := request(s, "GET", "/api/admins", "", w.Result().Cookies()[0], "", ""); w.Code != 403 {
		t.Fatal("temporary password granted full access")
	}
	challenge = totpChallenge(t, s, reset.TemporaryPassword)
	if _, err := db.ResetAdminTOTP(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	if w := totpPOST(t, s, "totp", map[string]string{"challenge_token": challenge, "code": totpCodeAt(t, testTOTPSecret, *clock)}, nil, ""); w.Code != 401 {
		t.Fatal("console reset left old challenge valid")
	}
	w = totpPOST(t, s, "login", map[string]string{"username": "admin", "password": reset.TemporaryPassword}, nil, "")
	if w.Code != 200 {
		t.Fatal("console factor reset did not restore sign-in")
	}
}

func TestTOTPChangesAreProtectedAndAtomicWithAudit(t *testing.T) {
	s, db, clock := totpFixture(t, false)
	owner, csrf := signIn(t, s)
	body := `{"current_password":"correct-password-123"}`
	for _, tc := range []struct {
		cookie       *http.Cookie
		csrf, origin string
		status       int
	}{
		{nil, "", s.cfg.PublicURL, 401}, {owner, "", s.cfg.PublicURL, 403}, {owner, csrf, "https://other.example.com", 403},
	} {
		if w := request(s, "POST", "/api/auth/totp/setup", body, tc.cookie, tc.csrf, tc.origin); w.Code != tc.status {
			t.Fatal("unprotected TOTP setup", w.Code)
		}
	}
	w := totpPOST(t, s, "totp/setup", map[string]string{"current_password": "correct-password-123"}, owner, csrf)
	var setup struct {
		Token  string `json:"setup_token"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &setup); err != nil || w.Code != 200 {
		t.Fatal("setup failed", w.Code)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_totp_enable BEFORE INSERT ON audit_events WHEN NEW.action='auth.totp.enabled' BEGIN SELECT RAISE(ABORT,'test'); END`); err != nil {
		t.Fatal(err)
	}
	if w := totpPOST(t, s, "totp/enable", map[string]string{"setup_token": setup.Token, "code": totpCodeAt(t, setup.Secret, *clock)}, owner, csrf); w.Code != 500 {
		t.Fatal("enable ignored audit failure")
	}
	var count int
	db.DB.QueryRow("SELECT count(*) FROM admin_totp").Scan(&count)
	if count != 0 {
		t.Fatal("failed enable left factor active")
	}
	db.DB.Exec("DROP TRIGGER fail_totp_enable")
	if w := totpPOST(t, s, "totp/enable", map[string]string{"setup_token": setup.Token, "code": totpCodeAt(t, setup.Secret, *clock)}, owner, csrf); w.Code != 200 {
		t.Fatal("failed enable consumed setup code")
	}
	*clock = clock.Add(30 * time.Second)
	challenge := totpChallenge(t, s, "correct-password-123")
	db.DB.Exec(`CREATE TRIGGER fail_totp_login BEFORE INSERT ON audit_events WHEN NEW.action='auth.login' BEGIN SELECT RAISE(ABORT,'test'); END`)
	if w := totpPOST(t, s, "totp", map[string]string{"challenge_token": challenge, "code": totpCodeAt(t, setup.Secret, *clock)}, nil, ""); w.Code != 500 || len(w.Result().Cookies()) != 0 {
		t.Fatal("login ignored audit failure")
	}
	db.DB.Exec("DROP TRIGGER fail_totp_login")
	if w := totpPOST(t, s, "totp", map[string]string{"challenge_token": challenge, "code": totpCodeAt(t, setup.Secret, *clock)}, nil, ""); w.Code != 200 {
		t.Fatal("failed login consumed code or challenge")
	}
	*clock = clock.Add(30 * time.Second)
	db.DB.Exec(`CREATE TRIGGER fail_totp_disable BEFORE INSERT ON audit_events WHEN NEW.action='auth.totp.disabled' BEGIN SELECT RAISE(ABORT,'test'); END`)
	if w := totpPOST(t, s, "totp/disable", map[string]string{"current_password": "correct-password-123", "code": totpCodeAt(t, setup.Secret, *clock)}, owner, csrf); w.Code != 500 {
		t.Fatal("disable ignored audit failure")
	}
	db.DB.QueryRow("SELECT count(*) FROM admin_totp").Scan(&count)
	if count != 1 {
		t.Fatal("failed disable removed factor")
	}
	db.DB.Exec("DROP TRIGGER fail_totp_disable")
	if w := totpPOST(t, s, "totp/disable", map[string]string{"current_password": "correct-password-123", "code": totpCodeAt(t, setup.Secret, *clock)}, owner, csrf); w.Code != 200 {
		t.Fatal("failed disable consumed code")
	}
}

func TestTOTPMissingKeyAndPasswordOnlyLoginRaceFailClosed(t *testing.T) {
	s, db, clock := totpFixture(t, true)
	var identity loginIdentity
	if err := db.DB.QueryRow("SELECT id,username,password_hash FROM admins WHERE id=1").Scan(&identity.ID, &identity.Username, &identity.PasswordHash); err != nil {
		t.Fatal(err)
	}
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.newLoginSession(httptest.NewRequest("POST", "/api/auth/login", nil), tx, identity)
	tx.Rollback()
	if !errors.Is(err, errLoginChanged) {
		t.Fatal("TOTP enable race allowed password-only login", err)
	}
	challenge := totpChallenge(t, s, "correct-password-123")
	if err := os.Remove(db.TOTPKeyPath()); err != nil {
		t.Fatal(err)
	}
	w := totpPOST(t, s, "totp", map[string]string{"challenge_token": challenge, "code": totpCodeAt(t, testTOTPSecret, *clock)}, nil, "")
	if w.Code != 500 || len(w.Result().Cookies()) != 0 {
		t.Fatal("missing encryption key bypassed TOTP")
	}
}

func TestTOTPSetupExpiresAndCannotTargetAnotherAccount(t *testing.T) {
	s, _, clock := totpFixture(t, false)
	owner, csrf := signIn(t, s)
	if w := totpPOST(t, s, "totp/setup", map[string]any{"current_password": "correct-password-123", "admin_id": 2}, owner, csrf); w.Code != 400 {
		t.Fatal("setup accepted an account selector")
	}
	w := totpPOST(t, s, "totp/setup", map[string]string{"current_password": "correct-password-123"}, owner, csrf)
	var setup struct {
		Token  string `json:"setup_token"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &setup); err != nil || w.Code != 200 {
		t.Fatal("setup missing")
	}
	*clock = clock.Add(11 * time.Minute)
	if w := totpPOST(t, s, "totp/enable", map[string]string{"setup_token": setup.Token, "code": totpCodeAt(t, setup.Secret, *clock)}, owner, csrf); w.Code != 409 {
		t.Fatal("expired setup enabled TOTP")
	}
}
