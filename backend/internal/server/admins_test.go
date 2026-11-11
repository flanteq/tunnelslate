package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func loginAdmin(t *testing.T, h http.Handler, name, password string) (*http.Cookie, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": name, "password": password})
	w := request(h, "POST", "/api/auth/login", string(body), nil, "", "https://desk.test")
	if w.Code != 200 {
		t.Fatalf("administrator login failed: %d", w.Code)
	}
	var result struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return w.Result().Cookies()[0], result.CSRF
}
func createAccount(t *testing.T, h http.Handler, cookie *http.Cookie, csrf, name string) (int64, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": name})
	w := request(h, "POST", "/api/admins", string(body), cookie, csrf, "https://desk.test")
	if w.Code != 201 {
		t.Fatalf("create administrator: %d %s", w.Code, w.Body.String())
	}
	var result struct {
		ID       int64  `json:"id"`
		Password string `json:"temporary_password"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Password) != 64 || result.ID <= 1 {
		t.Fatal("temporary credentials missing")
	}
	return result.ID, result.Password
}
func TestAdministratorListCurrentFirstThenAlphabetical(t *testing.T) {
	h, db, _ := fixture(t)
	root, _ := signIn(t, h)
	for _, name := range []string{"Zulu", "bravo", "Alpha"} {
		if _, err := db.DB.Exec(`INSERT INTO admins(username,password_hash,created_at,password_setup_required) SELECT ?,password_hash,created_at,0 FROM admins WHERE id=1`, name); err != nil {
			t.Fatal(err)
		}
	}
	other, _ := loginAdmin(t, h, "Zulu", "correct-password-123")
	for _, tc := range []struct {
		cookie *http.Cookie
		names  []string
	}{
		{root, []string{"admin", "Alpha", "bravo", "Zulu"}},
		{other, []string{"Zulu", "admin", "Alpha", "bravo"}},
	} {
		w := request(h, "GET", "/api/admins", "", tc.cookie, "", "")
		var accounts []adminAccount
		if err := json.Unmarshal(w.Body.Bytes(), &accounts); err != nil || w.Code != 200 || len(accounts) != len(tc.names) {
			t.Fatalf("list administrators: %d %s", w.Code, w.Body.String())
		}
		for i, a := range accounts {
			if a.Username != tc.names[i] || a.Current != (i == 0) {
				t.Fatalf("unexpected account at %d: %+v; expected %s", i, a, tc.names[i])
			}
		}
	}
}
func TestMultipleAdministratorLifecycleAndSessionIsolation(t *testing.T) {
	h, db, cfg := fixture(t)
	s := h.(*Server)
	root, csrf := signIn(t, h)
	id, temp := createAccount(t, h, root, csrf, "operator")
	path := fmt.Sprintf("/api/admins/%d", id)
	var saved string
	if err := db.DB.QueryRow("SELECT password_hash FROM admins WHERE id=?", id).Scan(&saved); err != nil || saved == temp {
		t.Fatal("raw password stored", err)
	}
	w := request(h, "GET", "/api/admins", "", root, "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), temp) || strings.Contains(w.Body.String(), saved) {
		t.Fatal("credentials leaked in list")
	}
	pending, pendingCSRF := loginAdmin(t, h, "OPERATOR", temp)
	for _, route := range []string{"/api/admins", "/api/clients", "/api/events"} {
		if request(h, "GET", route, "", pending, "", "").Code != 403 {
			t.Fatal("setup gate bypassed", route)
		}
	}
	if request(h, "POST", "/api/admins/1/delete", "{}", root, csrf, cfg.PublicURL).Code != 409 {
		t.Fatal("last configured administrator deleted")
	}
	rootReader := s.events.subscribe(tokenHash(root.Value))
	defer s.events.unsubscribe(rootReader)
	pendingReader := s.events.subscribe(tokenHash(pending.Value))
	defer s.events.unsubscribe(pendingReader)
	if w := request(h, "POST", "/api/auth/setup-password", `{"new_password":"operator-permanent-password"}`, pending, pendingCSRF, cfg.PublicURL); w.Code != 200 {
		t.Fatal("second account setup", w.Code, w.Body.String())
	}
	if len(rootReader.revoked) != 0 || len(pendingReader.revoked) != 1 {
		t.Fatal("password setup revoked unrelated event streams")
	}
	if request(h, "GET", "/api/auth/session", "", root, "", "").Code != 200 {
		t.Fatal("second account setup logged out the first")
	}
	operator, _ := loginAdmin(t, h, "operator", "operator-permanent-password")
	if w := request(h, "POST", path+"/rename", `{"username":"vpn-operator"}`, root, csrf, cfg.PublicURL); w.Code != 200 {
		t.Fatal("rename", w.Code, w.Body.String())
	}
	if request(h, "GET", "/api/auth/session", "", operator, "", "").Code != 401 {
		t.Fatal("rename kept old session")
	}
	operator, _ = loginAdmin(t, h, "vpn-operator", "operator-permanent-password")
	w = request(h, "POST", path+"/reset-password", "{}", root, csrf, cfg.PublicURL)
	if w.Code != 200 {
		t.Fatal("reset", w.Code)
	}
	var reset struct {
		Password string `json:"temporary_password"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reset); err != nil {
		t.Fatal(err)
	}
	if reset.Password == temp || len(reset.Password) != 64 {
		t.Fatal("reset did not rotate temporary secret")
	}
	if request(h, "GET", "/api/auth/session", "", operator, "", "").Code != 401 || request(h, "GET", "/api/auth/session", "", root, "", "").Code != 200 {
		t.Fatal("reset session isolation")
	}
	if err := db.Bootstrap(context.Background()); err != nil {
		t.Fatal("restart confused temporary account password with bootstrap file", err)
	}
	pending, pendingCSRF = loginAdmin(t, h, "vpn-operator", reset.Password)
	if w := request(h, "POST", "/api/auth/setup-password", `{"new_password":"operator-new-permanent-password"}`, pending, pendingCSRF, cfg.PublicURL); w.Code != 200 {
		t.Fatal("reset password setup", w.Code, w.Body.String())
	}
	operator, operatorCSRF := loginAdmin(t, h, "vpn-operator", "operator-new-permanent-password")
	if w := request(h, "POST", "/api/admins/1/delete", "{}", operator, operatorCSRF, cfg.PublicURL); w.Code != 200 {
		t.Fatal("cannot remove builtin account", w.Code, w.Body.String())
	}
	if request(h, "GET", "/api/auth/session", "", root, "", "").Code != 401 {
		t.Fatal("deleted administrator session survived")
	}
	if err := db.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	db.DB.QueryRow("SELECT count(*) FROM admins WHERE username='admin'").Scan(&count)
	if count != 0 {
		t.Fatal("bootstrap resurrected builtin admin")
	}
	if w := request(h, "POST", path+"/delete", "{}", operator, operatorCSRF, cfg.PublicURL); w.Code != 409 {
		t.Fatal("last administrator deleted", w.Code)
	}
	// Self-service password change must work for an ID other than 1.
	w = request(h, "POST", "/api/auth/password", `{"current_password":"operator-new-permanent-password","new_password":"operator-final-password-123"}`, operator, operatorCSRF, cfg.PublicURL)
	if w.Code != 200 {
		t.Fatal("second administrator cannot change own password", w.Code, w.Body.String())
	}
	if request(h, "GET", "/api/auth/session", "", operator, "", "").Code != 401 {
		t.Fatal("self password change retained session")
	}
	loginAdmin(t, h, "vpn-operator", "operator-final-password-123")
	for _, action := range []string{"admin.created", "admin.rename", "admin.password.reset", "admin.delete"} {
		db.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action=?", action).Scan(&count)
		if count != 1 {
			t.Fatal("missing administrator audit", action, count)
		}
	}
}
func TestAdministratorMutationGuardsAndAtomicAudit(t *testing.T) {
	h, db, cfg := fixture(t)
	root, csrf := signIn(t, h)
	for _, path := range []string{"/api/admins", "/api/admins/1/rename", "/api/admins/1/reset-password", "/api/admins/1/delete"} {
		if request(h, "POST", path, `{}`, nil, "", cfg.PublicURL).Code != 401 {
			t.Fatal("authentication guard", path)
		}
		if request(h, "POST", path, `{}`, root, "", cfg.PublicURL).Code != 403 {
			t.Fatal("CSRF guard", path)
		}
		if request(h, "POST", path, `{}`, root, csrf, "https://evil.test").Code != 403 {
			t.Fatal("origin guard", path)
		}
	}
	if request(h, "POST", "/api/admins", `{"username":"bad name"}`, root, csrf, cfg.PublicURL).Code != 400 {
		t.Fatal("invalid name accepted")
	}
	if request(h, "POST", "/api/admins", `{"username":"ADMIN"}`, root, csrf, cfg.PublicURL).Code != 409 {
		t.Fatal("case-insensitive duplicate accepted")
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_admin_audit BEFORE INSERT ON audit_events WHEN NEW.action='admin.created' BEGIN SELECT RAISE(FAIL,'test audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if w := request(h, "POST", "/api/admins", `{"username":"operator"}`, root, csrf, cfg.PublicURL); w.Code != 500 {
		t.Fatal("audit failure accepted", w.Code)
	}
	var n int
	db.DB.QueryRow("SELECT count(*) FROM admins").Scan(&n)
	if n != 1 {
		t.Fatal("creation audit rollback failed")
	}
	db.DB.Exec("DROP TRIGGER fail_admin_audit")
	id, temporary := createAccount(t, h, root, csrf, "operator")
	db.DB.Exec("UPDATE admins SET password_setup_required=0 WHERE id=?", id)
	other, _ := loginAdmin(t, h, "operator", temporary)
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_admin_reset BEFORE INSERT ON audit_events WHEN NEW.action='admin.password.reset' BEGIN SELECT RAISE(FAIL,'test audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if request(h, "POST", fmt.Sprintf("/api/admins/%d/reset-password", id), "{}", root, csrf, cfg.PublicURL).Code != 500 {
		t.Fatal("password reset audit failure accepted")
	}
	if request(h, "GET", "/api/auth/session", "", other, "", "").Code != 200 {
		t.Fatal("failed reset revoked sessions")
	}
	db.DB.Exec("DROP TRIGGER fail_admin_reset")

	if _, err := db.DB.Exec(`CREATE TRIGGER fail_admin_delete BEFORE INSERT ON audit_events WHEN NEW.action='admin.delete' BEGIN SELECT RAISE(FAIL,'test audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if request(h, "POST", fmt.Sprintf("/api/admins/%d/delete", id), "{}", root, csrf, cfg.PublicURL).Code != 500 {
		t.Fatal("delete audit failure accepted")
	}
	db.DB.QueryRow("SELECT count(*) FROM admins").Scan(&n)
	if n != 2 {
		t.Fatal("deletion audit rollback failed")
	}
	if request(h, "POST", "/api/admins/1/reset-password", "{}", root, csrf, cfg.PublicURL).Code != 409 {
		t.Fatal("own reset should use self-service password change")
	}
}
func TestConcurrentAdministratorDeletesKeepOneConfiguredAccount(t *testing.T) {
	h, db, cfg := fixture(t)
	root, csrf := signIn(t, h)
	id, temp := createAccount(t, h, root, csrf, "operator")
	pending, pendingCSRF := loginAdmin(t, h, "operator", temp)
	if request(h, "POST", "/api/auth/setup-password", `{"new_password":"operator-permanent-123"}`, pending, pendingCSRF, cfg.PublicURL).Code != 200 {
		t.Fatal("setup")
	}
	operator, otherCSRF := loginAdmin(t, h, "operator", "operator-permanent-123")
	var group sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 2)
	start := make(chan struct{})
	for _, job := range []struct {
		cookie     *http.Cookie
		csrf, path string
	}{{root, csrf, fmt.Sprintf("/api/admins/%d/delete", id)}, {operator, otherCSRF, "/api/admins/1/delete"}} {
		group.Add(1)
		go func(job struct {
			cookie     *http.Cookie
			csrf, path string
		}) {
			defer group.Done()
			<-start
			responses <- request(h, "POST", job.path, "{}", job.cookie, job.csrf, cfg.PublicURL)
		}(job)
	}
	close(start)
	group.Wait()
	close(responses)
	for response := range responses {
		if response.Code != 200 && response.Code != 401 && response.Code != 409 {
			t.Fatal("unexpected concurrent deletion response", response.Code)
		}
	}
	var count int
	if err := db.DB.QueryRow("SELECT count(*) FROM admins WHERE password_setup_required=0").Scan(&count); err != nil || count != 1 {
		t.Fatal("concurrent deletes locked out all administrators", err, count)
	}
}
func TestSelfRenameEndsOwnSessionsAndSurvivesBootstrap(t *testing.T) {
	h, db, cfg := fixture(t)
	root, csrf := signIn(t, h)
	w := request(h, "POST", "/api/admins/1/rename", `{"username":"owner"}`, root, csrf, cfg.PublicURL)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if request(h, "GET", "/api/auth/session", "", root, "", "").Code != 401 {
		t.Fatal("self rename retained session")
	}
	if err := db.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	cookie, _ := loginAdmin(t, h, "OWNER", "correct-password-123")
	w = request(h, "GET", "/api/auth/session", "", cookie, "", "")
	if !strings.Contains(w.Body.String(), `"username":"owner"`) {
		t.Fatal("canonical username missing")
	}
}

func TestResetBuiltinUsesTemporaryPasswordWithoutBootstrapFile(t *testing.T) {
	h, db, cfg := fixture(t)
	root, csrf := signIn(t, h)
	_, temporary := createAccount(t, h, root, csrf, "operator")
	pending, pendingCSRF := loginAdmin(t, h, "operator", temporary)
	if request(h, "POST", "/api/auth/setup-password", `{"new_password":"operator-permanent-123"}`, pending, pendingCSRF, cfg.PublicURL).Code != 200 {
		t.Fatal("setup")
	}
	operator, otherCSRF := loginAdmin(t, h, "operator", "operator-permanent-123")
	w := request(h, "POST", "/api/admins/1/reset-password", "{}", operator, otherCSRF, cfg.PublicURL)
	if w.Code != 200 {
		t.Fatal("builtin password reset", w.Code)
	}
	if err := db.Bootstrap(context.Background()); err != nil {
		t.Fatal("reset builtin required a bootstrap file", err)
	}
	if request(h, "GET", "/api/auth/session", "", root, "", "").Code != 401 {
		t.Fatal("old builtin session retained")
	}
	var result struct {
		Password string `json:"temporary_password"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	cookie, token := loginAdmin(t, h, "admin", result.Password)
	if request(h, "POST", "/api/auth/setup-password", `{"new_password":"restored-builtin-password"}`, cookie, token, cfg.PublicURL).Code != 200 {
		t.Fatal("reset builtin setup failed")
	}
	if err := db.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if request(h, "GET", "/api/auth/session", "", operator, "", "").Code != 200 {
		t.Fatal("builtin setup revoked operator")
	}
}
