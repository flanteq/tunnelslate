package server

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"tunnelslate/internal/pki"
)

func TestCertificateExpirationAPIAndRevocationMetadata(t *testing.T) {
	_, db, cfg := fixture(t)
	cfg.PKIDir = t.TempDir()
	cfg.OpenVPNDir = t.TempDir()
	cfg.CCDDir = t.TempDir()
	s, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.pki.Initialize(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	db.DB.Exec("INSERT INTO clients(id,name,created_at) VALUES ('alice','Alice',1)")
	admin, csrf := signIn(t, s)
	settings := request(s, "GET", "/api/settings", "", admin, "", "")
	var limits struct {
		MaxDate string `json:"certificate_max_date"`
	}
	caPEM, err := os.ReadFile(filepath.Join(cfg.PKIDir, "easyrsa", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	end := ca.NotAfter.UTC()
	last := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, time.UTC)
	if last.AddDate(0, 0, 1).Add(-time.Second).After(end) {
		last = last.AddDate(0, 0, -1)
	}
	if settings.Code != 200 || json.Unmarshal(settings.Body.Bytes(), &limits) != nil || limits.MaxDate != last.Format("2006-01-02") {
		t.Fatal("settings does not expose the actual CA date limit", settings.Code, settings.Body.String())
	}
	date := time.Now().UTC().AddDate(0, 0, 45).Format("2006-01-02")
	path := "/api/clients/alice/devices"
	if w := shareRequest(s, "POST", path, `{"name":"Phone","expires_on":"`+date+`"}`, nil, csrf, cfg.PublicURL, "http-expiry-issue01"); w.Code != 401 {
		t.Fatal("missing auth", w.Code)
	}
	if w := shareRequest(s, "POST", path, `{"name":"Phone","expires_on":"`+date+`"}`, admin, "", cfg.PublicURL, "http-expiry-issue01"); w.Code != 403 {
		t.Fatal("missing csrf", w.Code)
	}
	for i, date := range []string{"2000-01-01", "2099-01-01", "2027-02-30"} {
		w := shareRequest(s, "POST", path, `{"name":"Phone","expires_on":"`+date+`"}`, admin, csrf, cfg.PublicURL, fmt.Sprintf("http-expiry-invalid%d", i))
		if w.Code != 400 {
			t.Fatal("invalid expiry", w.Code, w.Body.String())
		}
	}
	w := shareRequest(s, "POST", path, `{"name":"Phone","expires_on":"`+date+`"}`, admin, csrf, cfg.PublicURL, "http-expiry-issue01")
	if w.Code != 200 {
		t.Fatal("issue expiry", w.Code, w.Body.String())
	}
	var issued struct {
		Operation struct {
			DeviceID string `json:"device_id"`
			Serial   string `json:"result_serial"`
		} `json:"operation"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	w = request(s, "GET", "/api/devices", "", admin, "", "")
	var devices []struct {
		ID      string `json:"id"`
		End     int64  `json:"not_after"`
		Revoked int64  `json:"revoked_at"`
	}
	if json.Unmarshal(w.Body.Bytes(), &devices) != nil || len(devices) != 1 || time.Unix(devices[0].End, 0).UTC().Format("2006-01-02 15:04:05") != date+" 23:59:59" {
		t.Fatal("wrong exact expiry in API", w.Code, w.Body.String())
	}
	revoked := time.Now().Unix()
	if _, err := db.DB.Exec("UPDATE certificates SET status='revoked',revoked_at=? WHERE serial=?", revoked, issued.Operation.Serial); err != nil {
		t.Fatal(err)
	}
	w = request(s, "GET", "/api/devices", "", admin, "", "")
	if json.Unmarshal(w.Body.Bytes(), &devices) != nil || devices[0].Revoked != revoked {
		t.Fatal("admin device lacks revocation date")
	}
	token := newShare(t, s, admin, csrf, "alice", false)
	public, _ := exchange(t, s, token)
	w = request(s, "GET", "/api/share/devices", "", public, "", "")
	var profiles struct {
		Devices []struct {
			Revoked int64 `json:"revoked_at"`
		} `json:"devices"`
	}
	if json.Unmarshal(w.Body.Bytes(), &profiles) != nil || len(profiles.Devices) != 1 || profiles.Devices[0].Revoked != revoked {
		t.Fatal("public profile lacks revocation date")
	}
}
func TestExpiredActiveSessionsAreDisconnectedAndAudited(t *testing.T) {
	_, db, cfg := fixture(t)
	cfg.ManagementSocket = filepath.Join(t.TempDir(), "mgmt.sock")
	expiredCN := "desk-" + strings.Repeat("a", 32)
	validCN := "desk-" + strings.Repeat("b", 32)
	db.DB.Exec("INSERT INTO clients(id,name,created_at) VALUES ('alice','Alice',1)")
	db.DB.Exec("INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES ('old','alice','Expired','device-old',1),('valid','alice','Valid','device-valid',1)")
	db.DB.Exec("INSERT INTO operations(id,kind,state,step,device_id,created_at,updated_at) VALUES ('old-op','issue','succeeded','complete','old',1,1),('valid-op','issue','succeeded','complete','valid',1,1)")
	if _, err := db.DB.Exec(`INSERT INTO certificates(serial,device_id,status,not_before,not_after,common_name,operation_id) VALUES ('AA','old','valid',1,?,?, 'old-op'),('BB','valid','valid',1,?,?,'valid-op')`, time.Now().Add(-time.Second).Unix(), expiredCN, time.Now().Add(time.Hour).Unix(), validCN); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", cfg.ManagementSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	active := map[string]bool{expiredCN: true, validCN: true}
	failKill := true
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				fmt.Fprintln(conn, ">INFO: ready")
				line, _ := bufio.NewReader(conn).ReadString('\n')
				line = strings.TrimSpace(line)
				mu.Lock()
				defer mu.Unlock()
				if line == "status 3" {
					fmt.Fprintln(conn, "TITLE\tOpenVPN test")
					fmt.Fprintln(conn, "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tBytes Received\tBytes Sent\tConnected Since (time_t)")
					for cn, yes := range active {
						if yes {
							fmt.Fprintf(conn, "CLIENT_LIST\t%s\t192.0.2.1:1000\t10.8.0.2\t100\t200\t1700000000\n", cn)
						}
					}
					fmt.Fprintln(conn, "END")
				} else if strings.HasPrefix(line, "kill ") {
					if failKill {
						fmt.Fprintln(conn, "ERROR: temporarily unavailable")
					} else {
						delete(active, strings.TrimPrefix(line, "kill "))
						fmt.Fprintln(conn, "SUCCESS: disconnected")
					}
				}
			}()
		}
	}()
	s, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := s.getLive(context.Background(), true)
	if len(snapshot.Connections) != 2 {
		t.Fatal("failed disconnection hidden from live state")
	}
	var count int
	db.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='session.expired'").Scan(&count)
	if count != 0 {
		t.Fatal("failed disconnect reported success")
	}
	mu.Lock()
	failKill = false
	mu.Unlock()
	snapshot = s.getLive(context.Background(), true)
	if len(snapshot.Connections) != 1 || snapshot.Connections[0].CommonName != validCN {
		t.Fatal("expired session survived or valid session was disconnected", snapshot.Connections)
	}
	s.getLive(context.Background(), true)
	db.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='session.expired' AND target=?", expiredCN).Scan(&count)
	if count != 1 {
		t.Fatal("expiration audit missing or duplicated", count)
	}
}

func TestCancelledExpiredIssuanceIsNotReportedAsRetryable(t *testing.T) {
	w := httptest.NewRecorder()
	(&Server{}).operationResponse(w, pki.Operation{ID: "expired-op", State: "failed"}, &pki.Error{Code: 409, Message: "Срок выпускаемого сертификата уже истёк; выпуск отменён"})
	if w.Code != 409 {
		t.Fatal("cancelled issuance incorrectly reported as retryable", w.Code)
	}
}
