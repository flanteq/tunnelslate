package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"tunnelslate/internal/metricsweb"
)

func TestPanelSettingsAccessRevisionAndNames(t *testing.T) {
	h, db, _ := fixture(t)
	s := h.(*Server)
	if w := request(h, "GET", "/api/panel-settings", "", nil, "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	cookie, csrf := signIn(t, h)
	get := request(h, "GET", "/api/panel-settings", "", cookie, "", "")
	if get.Code != 200 || !strings.Contains(get.Body.String(), `"metrics_enabled":false`) {
		t.Fatal(get.Code, get.Body.String())
	}
	w := request(h, "PUT", "/api/panel-settings/general", `{"instance_name":"Lab","revision":1}`, cookie, csrf, "https://desk.test")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = request(h, "PUT", "/api/panel-settings/general", `{"instance_name":"Stale","revision":1}`, cookie, csrf, "https://desk.test")
	if w.Code != 409 {
		t.Fatal(w.Code)
	}
	w = request(h, "PUT", "/api/panel-settings/general", `{"instance_name":"Line\nBreak","revision":2}`, cookie, csrf, "https://desk.test")
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	p, err := db.PanelSettings(context.Background())
	if err != nil || p.InstanceName != "Lab" {
		t.Fatal(p, err)
	}
	dash := request(h, "GET", "/api/dashboard", "", cookie, "", "")
	if !strings.Contains(dash.Body.String(), `"instance_name":"Lab"`) {
		t.Fatal("dashboard name missing")
	}
	// No main-port metrics, even with an authenticated panel session.
	if w = request(h, "GET", "/metrics", "", cookie, "", ""); w.Code != http.StatusNotFound {
		t.Fatal("metrics leaked through panel", w.Code)
	}
	// Explicitly activate an isolated ephemeral listener, without the background VPN worker.
	s.metrics = metricsweb.New("127.0.0.1:0", s.metricsHandler())
	s.metricsStarted.Store(true)
	defer s.metrics.Close()
	w = request(h, "PUT", "/api/panel-settings/metrics", `{"enabled":true,"mtls":true,"source":"pem","revision":2}`, cookie, csrf, "https://desk.test")
	if w.Code != 400 {
		t.Fatal("invalid TLS accepted", w.Code)
	}
	if s.metrics.Status().State != "disabled" {
		t.Fatal("invalid TLS opened socket")
	}
	w = request(h, "PUT", "/api/panel-settings/metrics", `{"enabled":true,"mtls":false,"source":"files","revision":2}`, cookie, csrf, "https://desk.test")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	response, err := http.Get("http://" + s.metrics.Status().Address + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	w = request(h, "PUT", "/api/panel-settings/metrics", `{"enabled":false,"mtls":false,"source":"files","revision":3}`, cookie, csrf, "https://desk.test")
	if w.Code != 200 || s.metrics.Status().State != "disabled" {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestMetricsTotalsCertificatesAndPersistentFailures(t *testing.T) {
	h, db, _ := fixture(t)
	s := h.(*Server)
	_, err := db.DB.Exec(`INSERT INTO clients(id,name,created_at) VALUES('alice','Alice',0);INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES('phone','alice','Phone','cn',0);INSERT INTO certificates(serial,device_id,status,not_before,not_after) VALUES('old','phone','revoked',1,9999999999),('new','phone','valid',2,9999999999);UPDATE vpn_stat_totals SET bytes_received=12345,bytes_sent=23456 WHERE kind='server';INSERT INTO login_ip_failures(ip,failed_at) VALUES('192.0.2.1',0);DELETE FROM login_ip_failures;INSERT INTO audit_events(actor,action,target,created_at,severity) VALUES('system','vpn.auth.reject','test',0,'WARNING');DELETE FROM audit_events WHERE action='vpn.auth.reject'`)
	if err != nil {
		t.Fatal(err)
	}
	s.live = &liveSnapshot{VPN: map[string]any{"state": "connected"}, PKIReady: true}
	s.liveAt = time.Now()
	recorder := request(s.metricsHandler(), "GET", "/metrics", "", nil, "", "")
	body := recorder.Body.String()
	for _, want := range []string{`tunnelslate_vpn_traffic_bytes_total{direction="received"} 12345`, `tunnelslate_vpn_traffic_bytes_total{direction="sent"} 23456`, `tunnelslate_authentication_failures_total{scope="panel"} 1`, `tunnelslate_authentication_failures_total{scope="vpn"} 1`, `serial="new"`, `tunnelslate_vpn_up 1`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(body, `serial="old"`) {
		t.Fatal("historical certificate leaked into profile series")
	}
	_, err = db.DB.Exec("UPDATE certificates SET status='revoked' WHERE serial='new'")
	if err != nil {
		t.Fatal(err)
	}
	body = request(s.metricsHandler(), "GET", "/metrics", "", nil, "", "").Body.String()
	if strings.Contains(body, "tunnelslate_profile_certificate_not_after_timestamp_seconds{") {
		t.Fatal("revoked certificate expiry exported")
	}
	s.liveAt = time.Now().Add(-time.Minute)
	body = request(s.metricsHandler(), "GET", "/metrics", "", nil, "", "").Body.String()
	if strings.Contains(body, "tunnelslate_vpn_connections ") {
		t.Fatal("stale connections presented as current")
	}
	if !strings.Contains(body, "tunnelslate_metrics_collection_success 0") {
		t.Fatal("stale snapshot not reported")
	}
}
func TestMetricsPrivateKeyEncryption(t *testing.T) {
	_, db, _ := fixture(t)
	ctx := context.Background()
	sealed, err := db.SealMetricsSecret(ctx, "server-key", "sensitive-key")
	if err != nil {
		t.Fatal(err)
	}
	p, err := db.PanelSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.EncryptedKey = sealed
	if err = db.SavePanelSettings(ctx, p, "admin", "panel.metrics.update"); err != nil {
		t.Fatal(err)
	}
	p, err = db.PanelSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), sealed) || strings.Contains(string(b), "sensitive-key") || !p.KeyConfigured {
		t.Fatal("secret leaked")
	}
	key, err := db.OpenMetricsSecret("server-key", p.EncryptedKey)
	if err != nil || key != "sensitive-key" {
		t.Fatal("cannot decrypt")
	}
	if _, err = db.OpenMetricsSecret("wrong-binding", p.EncryptedKey); err == nil {
		t.Fatal("secret substitution accepted")
	}
}

func TestPanelSettingsRejectsCSRFAndCannotOverwriteSecrets(t *testing.T) {
	h, db, _ := fixture(t)
	cookie, csrf := signIn(t, h)
	for _, route := range []string{"general", "metrics"} {
		for _, credentials := range []struct{ token, origin string }{{"", "https://desk.test"}, {csrf, "https://evil.test"}} {
			w := request(h, "PUT", "/api/panel-settings/"+route, `{"revision":1}`, cookie, credentials.token, credentials.origin)
			if w.Code != 403 {
				t.Fatal("CSRF bypass", route, w.Code)
			}
		}
	}
	w := request(h, "PUT", "/api/panel-settings/metrics", `{"enabled":false,"source":"files","revision":1,"encrypted_key":"attacker"}`, cookie, csrf, "https://desk.test")
	if w.Code != 400 {
		t.Fatal("unknown field accepted", w.Code)
	}
	p, err := db.PanelSettings(context.Background())
	if err != nil || p.Revision != 1 || p.EncryptedKey != "" {
		t.Fatal("rejected request mutated settings")
	}
}

func TestPanelSettingsAuditFailureRollsBackListenerAndDatabase(t *testing.T) {
	h, db, _ := fixture(t)
	s := h.(*Server)
	cookie, csrf := signIn(t, h)
	s.metrics = metricsweb.New("127.0.0.1:0", s.metricsHandler())
	s.metricsStarted.Store(true)
	defer s.metrics.Close()
	if _, err := db.DB.Exec(`CREATE TRIGGER reject_panel_audit BEFORE INSERT ON audit_events WHEN NEW.action='panel.metrics.update' BEGIN SELECT RAISE(ABORT,'test'); END`); err != nil {
		t.Fatal(err)
	}
	w := request(h, "PUT", "/api/panel-settings/metrics", `{"enabled":true,"mtls":false,"source":"files","revision":1}`, cookie, csrf, "https://desk.test")
	if w.Code != 500 {
		t.Fatal("audit failure ignored", w.Code)
	}
	if s.metrics.Status().State != "disabled" {
		t.Fatal("runtime not rolled back")
	}
	p, err := db.PanelSettings(context.Background())
	if err != nil || p.MetricsEnabled || p.Revision != 1 {
		t.Fatal("partial commit", err)
	}
}

func TestMetricsDatabaseFailureIsVisible(t *testing.T) {
	h, db, _ := fixture(t)
	s := h.(*Server)
	if _, err := db.DB.Exec("DROP TABLE monitoring_counters"); err != nil {
		t.Fatal(err)
	}
	w := request(s.metricsHandler(), "GET", "/metrics", "", nil, "", "")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `tunnelslate_component_up{component="database"} 0`) || !strings.Contains(body, "tunnelslate_metrics_collection_success 0") {
		t.Fatal("storage failure hidden")
	}
	if strings.Contains(body, "tunnelslate_vpn_traffic_bytes_total{") {
		t.Fatal("partial snapshot published")
	}
}

func TestMetricsRejectsKeysInPublicFieldsEvenWhenDisabled(t *testing.T) {
	h, db, _ := fixture(t)
	cookie, csrf := signIn(t, h)
	for _, field := range []string{"server_cert_pem", "client_ca_pem"} {
		body, _ := json.Marshal(map[string]any{"enabled": false, "source": "files", "revision": 1, field: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"})
		w := request(h, "PUT", "/api/panel-settings/metrics", string(body), cookie, csrf, "https://desk.test")
		if w.Code != 400 || !strings.Contains(w.Body.String(), "metrics.certificate_only") {
			t.Fatal("public field accepted secret", field, w.Code)
		}
	}
	p, err := db.PanelSettings(context.Background())
	if err != nil || p.Revision != 1 || p.ServerCert != "" || p.ClientCA != "" {
		t.Fatal("secret persisted in certificate fields")
	}
}
