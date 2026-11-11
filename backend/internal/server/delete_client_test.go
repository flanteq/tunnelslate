package server

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeleteEmptyClientWithoutPKIAndReuseName(t *testing.T) {
	_, db, cfg := fixture(t)
	cfg.PKIDir = t.TempDir()
	cfg.OpenVPNDir = t.TempDir()
	cfg.ManagementSocket = filepath.Join(t.TempDir(), "unavailable.sock")
	h, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := signIn(t, h)
	created := request(h, "POST", "/api/clients", `{"name":"Reusable client"}`, cookie, csrf, cfg.PublicURL)
	if created.Code != 201 {
		t.Fatal(created.Code)
	}
	var client struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &client); err != nil {
		t.Fatal(err)
	}
	path := "/api/clients/" + client.ID + "/delete"
	if w := request(h, "POST", path, `{}`, nil, "", cfg.PublicURL); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(h, "POST", path, `{}`, cookie, "", cfg.PublicURL); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request(h, "POST", path, `{}`, cookie, csrf, "https://evil.test"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
	r.AddCookie(cookie)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Origin", cfg.PublicURL)
	r.Header.Set("Idempotency-Key", "empty-client-delete-1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("delete empty client: %d %s", w.Code, w.Body.String())
	}
	if w := request(h, "GET", "/api/clients", "", cookie, "", ""); w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatal("deleted client still listed")
	}
	w = request(h, "GET", "/api/operations", "", cookie, "", "")
	var operations []map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &operations) != nil || len(operations) != 1 || operations[0]["client_id"] != client.ID || operations[0]["client_name"] != "Reusable client" || operations[0]["device_id"] != "" {
		t.Fatal("client-only operation missing or unreadable")
	}
	if w := request(h, "POST", "/api/clients", `{"name":"reusable CLIENT"}`, cookie, csrf, cfg.PublicURL); w.Code != 201 {
		t.Fatal("deleted client's name unavailable", w.Code)
	}
}
