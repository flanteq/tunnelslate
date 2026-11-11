package pki

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"tunnelslate/internal/vpnoptions"

	"tunnelslate/internal/management"
	"tunnelslate/internal/store"
)

type fakeManagement struct {
	mu        sync.Mutex
	active    map[string]bool
	addresses map[string]string
	socket    string
}

func newManagement(t *testing.T) *fakeManagement {
	t.Helper()
	m := &fakeManagement{active: map[string]bool{}, addresses: map[string]string{}, socket: filepath.Join(t.TempDir(), "mgmt.sock")}
	listener, err := net.Listen("unix", m.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				fmt.Fprintln(conn, ">INFO:management")
				scan := bufio.NewScanner(conn)
				if !scan.Scan() {
					return
				}
				command := scan.Text()
				m.mu.Lock()
				defer m.mu.Unlock()
				if command == "status 3" {
					fmt.Fprintln(conn, "TITLE\tOpenVPN test")
					fmt.Fprintln(conn, "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tBytes Received\tBytes Sent\tConnected Since (time_t)")
					for cn, active := range m.active {
						if active {
							address := m.addresses[cn]
							if address == "" {
								address = "10.8.0.2"
							}
							fmt.Fprintf(conn, "CLIENT_LIST\t%s\t192.0.2.1:1000\t%s\t100\t200\t1700000000\n", cn, address)
						}
					}
					fmt.Fprintln(conn, "END")
				} else if strings.HasPrefix(command, "kill ") {
					delete(m.active, strings.TrimPrefix(command, "kill "))
					fmt.Fprintln(conn, "SUCCESS: disconnected")
				} else {
					fmt.Fprintln(conn, "ERROR: bad command")
				}
			}()
		}
	}()
	return m
}
func (m *fakeManagement) connect(cn string) { m.mu.Lock(); defer m.mu.Unlock(); m.active[cn] = true }

func serviceFixture(t *testing.T) (*Service, *fakeManagement) {
	t.Helper()
	if _, err := os.Stat("/usr/share/easy-rsa/easyrsa"); err != nil {
		t.Skip("run inside the Docker backend-test image with pinned Easy-RSA")
	}
	root := t.TempDir()
	pkiDir := filepath.Join(root, "pki")
	runtime := filepath.Join(root, "runtime")
	for _, dir := range []string{pkiDir, runtime} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := store.Open(context.Background(), filepath.Join(root, "app", "desk.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.DB.Close() })
	m := newManagement(t)
	s := &Service{Store: db, PKIDir: pkiDir, RuntimeDir: runtime, Management: &management.Client{Socket: m.socket}}
	if err := s.Initialize(context.Background(), "test-admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("INSERT INTO clients(id,name,created_at) VALUES ('client','Test',?)", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	return s, m
}

func checkCRL(t *testing.T, s *Service, serials ...string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.RuntimeDir, "crl.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("bad CRL")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ca, _, err := readCert(s.path("ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, entry := range crl.RevokedCertificateEntries {
		found[Serial(entry.SerialNumber)] = true
	}
	for _, serial := range serials {
		if !found[serial] {
			t.Fatalf("serial %s missing in signed runtime CRL", serial)
		}
	}
}

func TestLifecycleRecoveryAndIdempotency(t *testing.T) {
	s, m := serviceFixture(t)
	ctx := context.Background()
	op, err := s.Start(ctx, "admin", "issue-request-000001", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	if op.State != "succeeded" || op.ResultSerial == "" {
		t.Fatalf("issue: %+v", op)
	}
	first := op.ResultSerial
	device := op.DeviceID
	profile, err := s.Profile(ctx, device, "vpn.example.com", 1195, "udp", "admin", vpnoptions.Link{TunMTU: 1400, MSSMode: "custom", MSS: 1320})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(profile.Content), "tun-mtu 1400\n# TCP MSS limited to 1320 bytes by the server\nmssfix 0\n") {
		t.Fatal("profile does not contain current link parameters")
	}
	if !strings.Contains(string(profile.Content), "remote vpn.example.com 1195\n") {
		t.Fatal("profile uses wrong external endpoint")
	}
	replay, err := s.Start(ctx, "admin", "issue-request-000001", "issue", "client", "Laptop")
	if err != nil || replay.ID != op.ID {
		t.Fatalf("idempotent replay: %+v %v", replay, err)
	}
	if _, err := s.Start(ctx, "admin", "issue-request-000001", "issue", "client", "Phone"); err == nil {
		t.Fatal("key reused for a different request")
	}
	_, args, err := s.operation(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	m.connect(args.CN)
	s.Management = &management.Client{Socket: filepath.Join(t.TempDir(), "offline.sock")}
	rotated, err := s.Start(ctx, "admin", "rotate-request-00001", "rotate", device, "")
	if err == nil || rotated.State != "partial" || rotated.Step != "disconnect_sessions" {
		t.Fatalf("expected partial disconnect: %+v %v", rotated, err)
	}
	checkCRL(t, s, first)
	if _, err := s.Profile(ctx, device, "vpn.example.com", 1195, "udp", "admin", vpnoptions.Link{}); err == nil {
		t.Fatal("unfinished replacement profile available")
	}
	// Simulate a process restart, then finish the SAME certificate and operation.
	resumed := &Service{Store: s.Store, PKIDir: s.PKIDir, RuntimeDir: s.RuntimeDir, Management: &management.Client{Socket: m.socket}}
	if err := resumed.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	finished, _, err := resumed.operation(ctx, rotated.ID)
	if err != nil || finished.State != "succeeded" || finished.ResultSerial != rotated.ResultSerial {
		t.Fatalf("recovery: %+v %v", finished, err)
	}
	second, err := resumed.Profile(ctx, device, "vpn.example.com", 1195, "tcp", "admin", vpnoptions.Link{})
	if err != nil {
		t.Fatal(err)
	}
	if string(second.Content) == string(profile.Content) || !strings.Contains(string(second.Content), "proto tcp-client") {
		t.Fatal("replacement profile did not change")
	}
	var count int
	if err := s.Store.DB.QueryRow("SELECT count(*) FROM certificates").Scan(&count); err != nil || count != 2 {
		t.Fatalf("duplicate issuance on recovery: %d %v", count, err)
	}
	connections, err := resumed.Management.Status(ctx)
	if err != nil || len(connections) != 0 {
		t.Fatal("old session survived recovery")
	}
	revoked, err := resumed.Start(ctx, "admin", "revoke-request-00001", "revoke", rotated.ResultSerial, "")
	if err != nil || revoked.State != "succeeded" {
		t.Fatalf("revoke: %+v %v", revoked, err)
	}
	checkCRL(t, resumed, first, rotated.ResultSerial)
	if _, err := resumed.Profile(ctx, device, "vpn.example.com", 1195, "udp", "admin", vpnoptions.Link{}); err == nil {
		t.Fatal("revoked profile available")
	}
}

func TestCRLPublishFailureIsRecoverable(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	op, err := s.Start(ctx, "admin", "issue-crl-request01", "issue", "client", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	crlPath := filepath.Join(s.RuntimeDir, "crl.pem")
	if err := os.Rename(crlPath, crlPath+".previous"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(crlPath, 0700); err != nil {
		t.Fatal(err)
	}
	partial, err := s.Start(ctx, "admin", "revoke-crl-request1", "revoke", op.ResultSerial, "")
	if err == nil || partial.State != "partial" || partial.Step != "publish_crl" {
		t.Fatalf("false success on CRL failure: %+v %v", partial, err)
	}
	index, err := s.index()
	if err != nil || index[op.ResultSerial] != "R" {
		t.Fatal("irreversible revocation was lost")
	}
	if err := os.Remove(crlPath); err != nil {
		t.Fatal(err)
	}
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	checkCRL(t, s, op.ResultSerial)
	completed, _, err := s.operation(ctx, partial.ID)
	if err != nil || completed.State != "succeeded" {
		t.Fatal("operation did not resume")
	}
}

func TestConcurrentDuplicateIssue(t *testing.T) {
	s, _ := serviceFixture(t)
	var wg sync.WaitGroup
	results := make(chan Operation, 2)
	failures := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op, err := s.Start(context.Background(), "admin", "same-request-000001", "issue", "client", "Concurrent")
			if err != nil {
				failures <- err
			} else {
				results <- op
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	first := ""
	for op := range results {
		if first != "" && first != op.ID {
			t.Fatal("duplicate concurrent operations")
		}
		first = op.ID
	}
	var count int
	if err := s.Store.DB.QueryRow("SELECT count(*) FROM certificates").Scan(&count); err != nil || count != 1 {
		t.Fatalf("certificate count %d: %v", count, err)
	}
}

func TestExternalProfilesAllowTimeForMFA(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	op, err := s.Start(ctx, "admin", "mfa-profile-check-001", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := s.Profile(ctx, op.DeviceID, "vpn.example.com", 1194, "udp", "admin", vpnoptions.Link{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(profile.Content), "hand-window") || strings.Contains(string(profile.Content), "auth-user-pass") {
		t.Fatal("certificate-only profile changed")
	}
	if _, err = s.Store.DB.Exec(`INSERT INTO vpn_auth_providers VALUES('mfa','MFA','radius',1,'{}','',1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Store.DB.Exec(`INSERT INTO client_vpn_auth VALUES('client','mfa','alice',1)`); err != nil {
		t.Fatal(err)
	}
	profile, err = s.Profile(ctx, op.DeviceID, "vpn.example.com", 1194, "udp", "admin", vpnoptions.Link{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(profile.Content), "auth-user-pass\nhand-window 330\n") {
		t.Fatal("external profile cannot wait for MFA")
	}
	if _, err = s.Store.DB.Exec(`UPDATE client_vpn_auth SET provider_id=NULL,username='',revision=2 WHERE client_id='client'`); err != nil {
		t.Fatal(err)
	}
	profile, err = s.Profile(ctx, op.DeviceID, "vpn.example.com", 1194, "udp", "admin", vpnoptions.Link{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(profile.Content), "auth-user-pass") {
		t.Fatal("client certificate-only policy ignored")
	}
}
