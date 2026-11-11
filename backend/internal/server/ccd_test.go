package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tunnelslate/internal/ccd"
	"tunnelslate/internal/pki"
	"tunnelslate/internal/vpnsettings"
)

func TestDeviceCCDAPIWithBasePathAndGlobalChanges(t *testing.T) {
	h, db, cfg := fixture(t)
	cookie, csrf := signIn(t, h)
	cfg.BasePath = "/ovpn"
	cfg.PKIDir = t.TempDir()
	cfg.OpenVPNDir = t.TempDir()
	cfg.CCDDir = t.TempDir()
	s, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO clients(id,name,created_at) VALUES ('client','Alice',0)`,
		`INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES ('device','client','Laptop','device-a',0)`,
		`INSERT INTO certificates(serial,device_id,status,not_before,not_after,common_name) VALUES ('AA','device','valid',1,4102444800,'desk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')`,
	} {
		if _, err := db.DB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	path := "/ovpn/api/devices/device/ccd"
	for _, method := range []string{"GET", "PUT"} {
		if w := request(s, method, path, `{}`, nil, "", ""); w.Code != 401 {
			t.Fatal("authentication", w.Code)
		}
	}
	w := request(s, "GET", path, "", cookie, "", "")
	var view pki.CCDView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil || w.Code != 200 || view.Settings.DNSMode != "inherit" {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	v := view.Settings
	v.StaticIP = "10.8.0.200"
	v.DNSDomainsMode = "custom"
	v.DNSDomain = "CONTRACTOR.example.com."
	v.DNSSearch = []string{"contractor.example.com"}
	v.RoutesMode = "custom"
	v.Routes = []string{"198.51.100.42/24"}
	body, _ := json.Marshal(map[string]any{"settings": v, "vpn_revision": view.VPN.Revision})
	if w := request(s, "PUT", path, string(body), cookie, "", cfg.PublicURL); w.Code != 403 {
		t.Fatal("CSRF", w.Code)
	}
	if w := request(s, "PUT", path, string(body), cookie, csrf, "https://evil.test"); w.Code != 403 {
		t.Fatal("origin", w.Code)
	}
	before := s.events.snapshot()["devices"]
	w = request(s, "PUT", path, string(body), cookie, csrf, cfg.PublicURL)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if s.events.snapshot()["devices"] <= before {
		t.Fatal("no SSE invalidation")
	}
	if w := request(s, "PUT", path, string(body), cookie, csrf, cfg.PublicURL); w.Code != 409 {
		t.Fatal("stale save", w.Code)
	}
	file := filepath.Join(cfg.CCDDir, "desk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	data, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(data), "198.51.100.0 255.255.255.0") || !strings.Contains(string(data), `push "dhcp-option DOMAIN contractor.example.com"`) {
		t.Fatal(string(data), err)
	}
	// A different global DNS must update this custom-routes CCD before restart.
	var global vpnsettings.Settings
	w = request(s, "GET", "/ovpn/api/settings", "", cookie, "", "")
	var settings struct {
		VPN vpnsettings.Settings `json:"vpn"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &settings); err != nil {
		t.Fatal(err)
	}
	global = settings.VPN
	global.DNS = []string{"203.0.113.53"}
	global.DNSDomain = "office.example.com"
	global.DNSSearch = []string{"dev.example.com"}
	global.TunMTU, global.MSSMode, global.MSS = 1400, "custom", 1320
	body, _ = json.Marshal(global)
	w = request(s, "PUT", "/ovpn/api/settings/vpn", string(body), cookie, csrf, cfg.PublicURL)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &global); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(file)
	if err != nil || !strings.Contains(string(data), "203.0.113.53 255.255.255.255") {
		t.Fatal("global DNS not republished", string(data), err)
	}
	global.Network = "10.9.0.0/24"
	body, _ = json.Marshal(global)
	if w := request(s, "PUT", "/ovpn/api/settings/vpn", string(body), cookie, csrf, cfg.PublicURL); w.Code != 409 {
		t.Fatal("network orphaned static IP", w.Code, w.Body.String())
	}
	w = request(s, "GET", "/ovpn/api/devices", "", cookie, "", "")
	var devices []struct {
		StaticIP string `json:"static_ip"`
		Custom   bool   `json:"custom_ccd"`
		Pending  bool   `json:"ccd_pending"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &devices); err != nil || len(devices) != 1 || devices[0].StaticIP != "10.8.0.200" || !devices[0].Custom || devices[0].Pending {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	// Global and per-device domains are independent, including after restart.
	w = request(s, "GET", path, "", cookie, "", "")
	var updated pki.CCDView
	if err := json.Unmarshal(w.Body.Bytes(), &updated); err != nil || updated.Settings.DNSDomain != "contractor.example.com" || updated.VPN.DNSDomain != "office.example.com" || len(updated.VPN.DNSSearch) != 1 {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	// Request validation rejects directives instead of writing arbitrary config.
	view.Settings = ccd.Defaults()
	view.Settings.Revision = 1
	view.Settings.DNSMode = "custom"
	view.Settings.DNS = []string{"192.0.2.53\nscript-security 2"}
	body, _ = json.Marshal(map[string]any{"settings": view.Settings, "vpn_revision": global.Revision})
	if w := request(s, "PUT", path, string(body), cookie, csrf, cfg.PublicURL); w.Code != 400 {
		t.Fatal("invalid DNS accepted", w.Code, w.Body.String())
	}
}
