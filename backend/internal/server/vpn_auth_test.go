package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestVPNAuthConfigurationRequiresAdminAndCSRFAndNeverReturnsSecrets(t *testing.T) {
	h, db, _ := fixture(t)
	const body = `{"name":"Office","kind":"radius","enabled":true,"secret":"test-shared-secret","config":{"address":"127.0.0.1:1812","timeout_seconds":120}}`
	for _, path := range []string{"/api/vpn-auth/providers", "/api/clients/example/vpn-auth"} {
		if w := request(h, "GET", path, "", nil, "", ""); w.Code != http.StatusUnauthorized {
			t.Fatal(path, w.Code)
		}
	}
	cookie, csrf := signIn(t, h)
	for _, method := range []string{"GET", "PUT"} {
		w := request(h, method, "/api/devices/example/vpn-auth", `{"mode":"certificate"}`, cookie, csrf, "")
		if w.Code != 404 && w.Code != 405 {
			t.Fatal("device authentication endpoint still exists", method, w.Code)
		}
	}

	if w := request(h, "POST", "/api/vpn-auth/providers", strings.Replace(body, `"timeout_seconds":120`, `"timeout_seconds":301`, 1), cookie, csrf, ""); w.Code != 400 || !strings.Contains(w.Body.String(), "vpn_auth.invalid_radius_timeout") {
		t.Fatal("out-of-range timeout accepted", w.Code, w.Body.String())
	}
	if w := request(h, "POST", "/api/vpn-auth/providers", body, cookie, "", ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	w := request(h, "POST", "/api/vpn-auth/providers", body, cookie, csrf, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "test-shared-secret") {
		t.Fatal("plaintext returned")
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["config"].(map[string]any)["timeout_seconds"] != float64(120) {
		t.Fatal("configured timeout missing from provider response")
	}
	w = request(h, "GET", "/api/vpn-auth/providers", "", cookie, "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "test-shared-secret") {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err := db.DB.Exec("INSERT INTO clients(id,name,created_at) VALUES('c','Client',1)"); err != nil {
		t.Fatal(err)
	}
	b := `{"mode":"external","provider_id":"` + result["id"].(string) + `","username":"alice","revision":0}`
	w = request(h, "PUT", "/api/clients/c/vpn-auth", b, cookie, csrf, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = request(h, "GET", "/api/clients", "", cookie, "", "")
	var clients []struct {
		External bool `json:"external_auth"`
		Enabled  bool `json:"auth_provider_enabled"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &clients) != nil || len(clients) != 1 || !clients[0].External || !clients[0].Enabled {
		t.Fatal("client authentication indicator missing", w.Code, w.Body.String())
	}
	if _, err := db.DB.Exec("UPDATE vpn_auth_providers SET enabled=0"); err != nil {
		t.Fatal(err)
	}
	w = request(h, "GET", "/api/clients", "", cookie, "", "")
	if json.Unmarshal(w.Body.Bytes(), &clients) != nil || !clients[0].External || clients[0].Enabled {
		t.Fatal("disabled provider indicator incorrect", w.Body.String())
	}
	if _, err := db.DB.Exec("UPDATE vpn_auth_providers SET enabled=1"); err != nil {
		t.Fatal(err)
	}
	if w = request(h, "PUT", "/api/clients/c/vpn-auth", b, cookie, csrf, ""); w.Code != 409 {
		t.Fatal("stale binding accepted", w.Code)
	}
}
