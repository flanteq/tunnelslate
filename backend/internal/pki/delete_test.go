package pki

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"tunnelslate/internal/vpnoptions"

	"tunnelslate/internal/management"
)

func assertDeleted(t *testing.T, s *Service, deviceID string, expected bool) {
	t.Helper()
	var deleted sql.NullInt64
	if err := s.Store.DB.QueryRow("SELECT deleted_at FROM devices WHERE id=?", deviceID).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if deleted.Valid != expected {
		t.Fatalf("deleted=%t expected=%t", deleted.Valid, expected)
	}
}

func TestDeleteRevokesAllCertificatesAndAllowsNameReuse(t *testing.T) {
	s, m := serviceFixture(t)
	ctx := context.Background()
	issued, err := s.Start(ctx, "admin", "delete-issue-request01", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	_, original, _ := s.operation(ctx, issued.ID)
	originalCert, _, err := readCert(s.path("issued", original.CN+".crt"))
	if err != nil {
		t.Fatal(err)
	}
	originalKey, err := os.ReadFile(s.path("private", original.CN+".key"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := s.Start(ctx, "admin", "delete-rotate-request1", "rotate", issued.DeviceID, "")
	if err != nil {
		t.Fatal(err)
	}
	_, current, _ := s.operation(ctx, rotated.ID)
	m.connect(original.CN)
	m.connect(current.CN)
	deleted, err := s.Start(ctx, "admin", "delete-profile-request1", "delete", issued.DeviceID, "")
	if err != nil || deleted.State != "succeeded" {
		t.Fatalf("delete state=%s err=%v", deleted.State, err)
	}
	assertDeleted(t, s, issued.DeviceID, true)
	checkCRL(t, s, issued.ResultSerial, rotated.ResultSerial)
	connections, err := s.Management.Status(ctx)
	if err != nil || len(connections) != 0 {
		t.Fatal("deleted profile still has sessions")
	}
	if _, err := s.Profile(ctx, issued.DeviceID, "vpn.test", 1195, "udp", "admin", vpnoptions.Link{}); err == nil {
		t.Fatal("deleted profile can be downloaded")
	}
	if _, err := s.Start(ctx, "admin", "rotate-deleted-request1", "rotate", issued.DeviceID, ""); err == nil {
		t.Fatal("deleted profile can be rotated")
	}
	retainedKey, err := os.ReadFile(s.path("private", original.CN+".key"))
	if errors.Is(err, os.ErrNotExist) {
		// Easy-RSA 3.2.5 archives revoked keys by certificate serial.
		archiveName := fmt.Sprintf("%X.key", originalCert.SerialNumber.Bytes())
		retainedKey, err = os.ReadFile(s.path("revoked", "private_by_serial", archiveName))
	}
	if err != nil || !bytes.Equal(retainedKey, originalKey) {
		t.Fatalf("PKI key history was not preserved: %v", err)
	}
	replayed, err := s.Start(ctx, "admin", "delete-profile-request1", "delete", issued.DeviceID, "")
	if err != nil || replayed.ID != deleted.ID {
		t.Fatal("delete retry was not idempotent")
	}
	var total, revoked, audit int
	if err := s.Store.DB.QueryRow("SELECT count(*),sum(status='revoked') FROM certificates WHERE device_id=?", issued.DeviceID).Scan(&total, &revoked); err != nil || total != 2 || revoked != 2 {
		t.Fatalf("certificate history total=%d revoked=%d err=%v", total, revoked, err)
	}
	if err := s.Store.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='pki.delete'").Scan(&audit); err != nil || audit != 1 {
		t.Fatal("delete audit not exactly once")
	}
	replacement, err := s.Start(ctx, "admin", "replacement-issue-0001", "issue", "client", "Laptop")
	if err != nil || replacement.DeviceID == issued.DeviceID {
		t.Fatalf("deleted name cannot be reused: %v", err)
	}
}

func TestDeleteFailureKeepsProfileVisibleUntilRecovery(t *testing.T) {
	s, m := serviceFixture(t)
	ctx := context.Background()
	issued, err := s.Start(ctx, "admin", "delete-recover-issue1", "issue", "client", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	_, args, _ := s.operation(ctx, issued.ID)
	m.connect(args.CN)
	s.Management = &management.Client{Socket: s.RuntimeDir + "/unavailable.sock"}
	partial, err := s.Start(ctx, "admin", "delete-recovery-key01", "delete", issued.DeviceID, "")
	if err == nil || partial.State != "partial" || partial.Step != "disconnect_sessions" {
		t.Fatalf("unexpected partial operation: %+v err=%v", partial, err)
	}
	assertDeleted(t, s, issued.DeviceID, false)
	checkCRL(t, s, issued.ResultSerial)
	restarted := &Service{Store: s.Store, PKIDir: s.PKIDir, RuntimeDir: s.RuntimeDir, Management: &management.Client{Socket: m.socket}}
	if err := restarted.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	assertDeleted(t, s, issued.DeviceID, true)
	op, _, err := s.operation(ctx, partial.ID)
	if err != nil || op.State != "succeeded" {
		t.Fatal("delete did not resume")
	}
}

func TestDeleteAlreadyRevokedProfileOfDisabledClient(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	issued, err := s.Start(ctx, "admin", "delete-revoked-issue1", "issue", "client", "Tablet")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(ctx, "admin", "delete-revoked-revoke1", "revoke", issued.ResultSerial, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.DB.Exec("UPDATE clients SET disabled=1 WHERE id='client'"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(ctx, "admin", "delete-revoked-delete1", "delete", issued.DeviceID, ""); err != nil {
		t.Fatal(err)
	}
	assertDeleted(t, s, issued.DeviceID, true)
	var count int
	if err := s.Store.DB.QueryRow("SELECT count(*) FROM certificates").Scan(&count); err != nil || count != 1 {
		t.Fatal("deletion issued an extra certificate")
	}
}

func TestDeleteHidingAndAuditAreAtomic(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	issued, err := s.Start(ctx, "admin", "delete-atomic-issue1", "issue", "client", "Desktop")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.DB.Exec(`CREATE TRIGGER fail_delete_audit BEFORE INSERT ON audit_events WHEN NEW.action='pki.delete' BEGIN SELECT RAISE(FAIL,'simulated delete audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	partial, err := s.Start(ctx, "admin", "delete-atomic-request1", "delete", issued.DeviceID, "")
	if err == nil || partial.State != "partial" || partial.Step != "delete_profile" {
		t.Fatalf("state=%s step=%s err=%v", partial.State, partial.Step, err)
	}
	assertDeleted(t, s, issued.DeviceID, false)
	if _, err := s.Store.DB.Exec("DROP TRIGGER fail_delete_audit"); err != nil {
		t.Fatal(err)
	}
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	assertDeleted(t, s, issued.DeviceID, true)
	_, err = s.Start(ctx, "admin", "delete-again-newkey1", "delete", issued.DeviceID, "")
	var problem *Error
	if !errors.As(err, &problem) || problem.Code != 404 {
		t.Fatal("deleted device accepted a new delete operation")
	}
}
