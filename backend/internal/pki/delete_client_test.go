package pki

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"tunnelslate/internal/vpnoptions"

	"tunnelslate/internal/management"
)

func assertClientDeleted(t *testing.T, s *Service, clientID string, expected bool) {
	t.Helper()
	var deleted sql.NullInt64
	if err := s.Store.DB.QueryRow("SELECT deleted_at FROM clients WHERE id=?", clientID).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if deleted.Valid != expected {
		t.Fatalf("client deleted=%t expected=%t", deleted.Valid, expected)
	}
}

func assertConflict(t *testing.T, err error) {
	t.Helper()
	var expected *Error
	if !errors.As(err, &expected) || expected.Code != 409 {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestDeleteClientRevokesAllProfilesAndPreservesOtherClients(t *testing.T) {
	s, m := serviceFixture(t)
	ctx := context.Background()
	laptop, err := s.Start(ctx, "admin", "client-delete-laptop1", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	phone, err := s.Start(ctx, "admin", "client-delete-phone01", "issue", "client", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := s.Start(ctx, "admin", "client-delete-rotate1", "rotate", laptop.DeviceID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(ctx, "admin", "client-delete-device1", "delete", phone.DeviceID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.DB.Exec("INSERT INTO clients(id,name,created_at) VALUES ('other','Other',1)"); err != nil {
		t.Fatal(err)
	}
	other, err := s.Start(ctx, "admin", "client-delete-other01", "issue", "other", "Other laptop")
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []Operation{laptop, phone, rotated, other} {
		_, args, err := s.operation(ctx, op.ID)
		if err != nil {
			t.Fatal(err)
		}
		m.connect(args.CN)
	}
	deleted, err := s.Start(ctx, "admin", "client-delete-request1", "delete_client", "client", "")
	if err != nil || deleted.State != "succeeded" || deleted.ClientID != "client" || deleted.DeviceID != "" {
		t.Fatalf("delete=%+v err=%v", deleted, err)
	}
	assertClientDeleted(t, s, "client", true)
	assertDeleted(t, s, laptop.DeviceID, true)
	assertDeleted(t, s, phone.DeviceID, true)
	assertClientDeleted(t, s, "other", false)
	assertDeleted(t, s, other.DeviceID, false)
	checkCRL(t, s, laptop.ResultSerial, phone.ResultSerial, rotated.ResultSerial)
	var count int
	if err := s.Store.DB.QueryRow(`SELECT count(*) FROM certificates c JOIN devices d ON d.id=c.device_id WHERE d.client_id='client' AND c.status='revoked'`).Scan(&count); err != nil || count != 3 {
		t.Fatal("client certificate history not retained/revoked")
	}
	connections, err := s.Management.Status(ctx)
	_, otherArgs, _ := s.operation(ctx, other.ID)
	if err != nil || len(connections) != 1 || connections[0].CommonName != otherArgs.CN {
		t.Fatal("unrelated client disconnected or target sessions survived")
	}
	if _, err := s.Profile(ctx, other.DeviceID, "vpn.test", 1195, "udp", "admin", vpnoptions.Link{}); err != nil {
		t.Fatal("unrelated client lost profile access", err)
	}
	if _, err := s.Profile(ctx, laptop.DeviceID, "vpn.test", 1195, "udp", "admin", vpnoptions.Link{}); err == nil {
		t.Fatal("deleted client's profile downloadable")
	}
	if _, err := s.Start(ctx, "admin", "client-delete-newdev1", "issue", "client", "New"); err == nil {
		t.Fatal("deleted client accepted new device")
	}
	replayed, err := s.Start(ctx, "admin", "client-delete-request1", "delete_client", "client", "")
	if err != nil || replayed.ID != deleted.ID {
		t.Fatal("client deletion not idempotent")
	}
	if err := s.Store.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='pki.delete_client' AND target='client'").Scan(&count); err != nil || count != 1 {
		t.Fatal("client deletion audit not exactly once")
	}
	if _, err := s.Store.DB.Exec("INSERT INTO clients(id,name,created_at) VALUES ('replacement','Test',1)"); err != nil {
		t.Fatal("deleted client name cannot be reused", err)
	}
}

func TestDeleteClientPartialBlocksNewProfilesAndRecovers(t *testing.T) {
	s, m := serviceFixture(t)
	ctx := context.Background()
	var devices []Operation
	for i, name := range []string{"Laptop", "Phone"} {
		key := []string{"partial-client-issue1", "partial-client-issue2"}[i]
		op, err := s.Start(ctx, "admin", key, "issue", "client", name)
		if err != nil {
			t.Fatal(err)
		}
		devices = append(devices, op)
		_, args, _ := s.operation(ctx, op.ID)
		m.connect(args.CN)
	}
	s.Management = &management.Client{Socket: s.RuntimeDir + "/unavailable.sock"}
	partial, err := s.Start(ctx, "admin", "partial-client-delete1", "delete_client", "client", "")
	if err == nil || partial.State != "partial" || partial.Step != "disconnect_sessions" {
		t.Fatalf("partial=%+v err=%v", partial, err)
	}
	assertClientDeleted(t, s, "client", false)
	for _, op := range devices {
		assertDeleted(t, s, op.DeviceID, false)
	}
	_, err = s.Start(ctx, "admin", "partial-client-new01", "issue", "client", "New laptop")
	assertConflict(t, err)
	_, err = s.Start(ctx, "admin", "partial-client-rotate1", "rotate", devices[0].DeviceID, "")
	assertConflict(t, err)
	_, err = s.Start(ctx, "admin", "partial-client-again1", "delete_client", "client", "")
	assertConflict(t, err)
	var count int
	if err := s.Store.DB.QueryRow("SELECT count(*) FROM devices WHERE client_id='client'").Scan(&count); err != nil || count != 2 {
		t.Fatal("blocked issue created a device")
	}
	if _, err := s.Store.DB.Exec("INSERT INTO clients(id,name,created_at) VALUES ('other','Other',1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(ctx, "admin", "partial-client-other1", "issue", "other", "Laptop"); err != nil {
		t.Fatal("client deletion blocked unrelated client", err)
	}
	restarted := &Service{Store: s.Store, PKIDir: s.PKIDir, RuntimeDir: s.RuntimeDir, Management: &management.Client{Socket: m.socket}}
	if err := restarted.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	assertClientDeleted(t, s, "client", true)
	for _, op := range devices {
		assertDeleted(t, s, op.DeviceID, true)
	}
}

func TestDeleteClientWaitsForUnfinishedDeviceOperation(t *testing.T) {
	s, m := serviceFixture(t)
	ctx := context.Background()
	op, err := s.Start(ctx, "admin", "client-busy-issue01", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	s.Management = &management.Client{Socket: s.RuntimeDir + "/unavailable.sock"}
	if _, err := s.Start(ctx, "admin", "client-busy-rotate01", "rotate", op.DeviceID, ""); err == nil {
		t.Fatal("expected partial rotation")
	}
	_, err = s.Start(ctx, "admin", "client-busy-delete01", "delete_client", "client", "")
	assertConflict(t, err)
	assertClientDeleted(t, s, "client", false)
	s.Management = &management.Client{Socket: m.socket}
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(ctx, "admin", "client-busy-delete01", "delete_client", "client", ""); err != nil {
		t.Fatal(err)
	}
	assertClientDeleted(t, s, "client", true)
}

func TestDeleteClientHidingIsAtomicWithAudit(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	op, err := s.Start(ctx, "admin", "client-atomic-issue1", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.DB.Exec(`CREATE TRIGGER fail_client_audit BEFORE INSERT ON audit_events WHEN NEW.action='pki.delete_client' BEGIN SELECT RAISE(FAIL,'simulated audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	partial, err := s.Start(ctx, "admin", "client-atomic-delete1", "delete_client", "client", "")
	if err == nil || partial.State != "partial" || partial.Step != "delete_client" {
		t.Fatalf("partial=%+v err=%v", partial, err)
	}
	assertClientDeleted(t, s, "client", false)
	assertDeleted(t, s, op.DeviceID, false)
	if _, err := s.Store.DB.Exec("DROP TRIGGER fail_client_audit"); err != nil {
		t.Fatal(err)
	}
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	assertClientDeleted(t, s, "client", true)
	assertDeleted(t, s, op.DeviceID, true)
}
