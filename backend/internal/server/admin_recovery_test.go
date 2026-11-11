package server

import (
	"context"
	"strings"
	"testing"

	"tunnelslate/internal/store"
)

func TestConsoleRecoveryRevokesSessionsAndRequiresPasswordSetup(t *testing.T) {
	h, _, cfg := fixture(t)
	s := h.(*Server)
	old, _ := signIn(t, h)
	oldReader, oldResponse := openStream(t, s, "", old)
	if event, _ := readEvent(t, oldReader); event != "ready" {
		t.Fatal("stream not ready")
	}
	// Open the same file as a second process would, while the web server runs.
	console, err := store.Open(context.Background(), cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer console.DB.Close()
	created, err := console.RecoverAdmin(context.Background(), "second-owner", true)
	if err != nil {
		t.Fatal(err)
	}
	var revision int64
	before := s.events.snapshot()
	if err := s.syncConsoleAdmins(context.Background(), &revision); err != nil {
		t.Fatal(err)
	}
	if s.events.snapshot()["admins"] <= before["admins"] || s.events.snapshot()["audit"] <= before["audit"] {
		t.Fatal("console changes not published")
	}
	if event, _ := readEvent(t, oldReader); event != "state" {
		t.Fatal("console create not delivered")
	}
	oldResponse.Body.Close()
	temporary, csrf := loginAdmin(t, h, created.Username, created.TemporaryPassword)
	if w := request(h, "GET", "/api/admins", "", temporary, "", ""); w.Code != 403 {
		t.Fatal("temporary password bypassed setup")
	}
	if w := request(h, "POST", "/api/auth/setup-password", `{"new_password":"second-owner-permanent-password"}`, temporary, csrf, cfg.PublicURL); w.Code != 200 {
		t.Fatal("new administrator setup failed", w.Code)
	}
	other, _ := loginAdmin(t, h, "second-owner", "second-owner-permanent-password")
	oldReader, _ = openStream(t, s, "", old)
	if event, _ := readEvent(t, oldReader); event != "ready" {
		t.Fatal("stream not ready after other account setup")
	}
	reset, err := console.RecoverAdmin(context.Background(), "admin", false)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(h, "GET", "/api/auth/session", "", old, "", ""); w.Code != 401 {
		t.Fatal("old session survived console reset")
	}
	if w := request(h, "GET", "/api/auth/session", "", other, "", ""); w.Code != 200 {
		t.Fatal("reset signed out another administrator")
	}
	if err := s.syncConsoleAdmins(context.Background(), &revision); err != nil {
		t.Fatal(err)
	}
	if event, _ := readEvent(t, oldReader); event != "session-expired" {
		t.Fatal("reset stream not closed")
	}
	if w := request(h, "POST", "/api/auth/login", `{"username":"admin","password":"correct-password-123"}`, nil, "", cfg.PublicURL); w.Code != 401 {
		t.Fatal("old password survived console reset")
	}
	pending, token := loginAdmin(t, h, reset.Username, reset.TemporaryPassword)
	for _, path := range []string{"/api/dashboard", "/api/clients", "/api/admins", "/api/events"} {
		if w := request(h, "GET", path, "", pending, "", ""); w.Code != 403 || !strings.Contains(w.Body.String(), "password_setup_required") {
			t.Fatal("recovered administrator bypassed setup", path, w.Code)
		}
	}
	if w := request(h, "POST", "/api/auth/setup-password", `{"new_password":"recovered-permanent-password"}`, pending, token, cfg.PublicURL); w.Code != 200 {
		t.Fatal("recovery password setup failed", w.Code)
	}
	loginAdmin(t, h, "admin", "recovered-permanent-password")
	if w := request(h, "POST", "/api/auth/login", `{"username":"admin","password":"`+reset.TemporaryPassword+`"}`, nil, "", cfg.PublicURL); w.Code != 401 {
		t.Fatal("temporary password survived setup")
	}
}
