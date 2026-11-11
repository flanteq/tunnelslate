package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func auditRetentionStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "desk.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	return s
}

func TestAuditRetentionUsesEventTimeAndIncludesCriticalEvents(t *testing.T) {
	s := auditRetentionStore(t)
	for _, tc := range []struct {
		action, severity string
		created          int64
	}{
		{"fresh", "INFO", 1001}, {"old", "INFO", 999}, {"future", "INFO", 2000}, {"critical", "CRITICAL", 998}, {"boundary", "INFO", 1000},
	} {
		if _, err := s.DB.Exec("INSERT INTO audit_events(actor,action,severity,created_at) VALUES ('admin',?,?,?)", tc.action, tc.severity, tc.created); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(`INSERT INTO admins(username,password_hash,created_at) VALUES ('admin','hash',0);
 INSERT INTO clients(id,name,created_at) VALUES ('client','Client',0);
 INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES ('device','client','Device','cn',0);
 INSERT INTO certificates(serial,device_id,status,not_before,not_after) VALUES ('serial','device','revoked',0,1);
 INSERT INTO operations(id,kind,state,step,created_at,updated_at) VALUES ('operation','issue','succeeded','complete',0,0)`); err != nil {
		t.Fatal(err)
	}
	removed, err := s.PruneAuditBefore(context.Background(), 1000)
	if err != nil || removed != 3 {
		t.Fatalf("cleanup: %d %v", removed, err)
	}
	for _, action := range []string{"fresh", "future"} {
		var count int
		if err := s.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action=?", action).Scan(&count); err != nil || count != 1 {
			t.Fatal("recent event lost", action, err)
		}
	}
	for _, table := range []string{"admins", "clients", "devices", "certificates", "operations"} {
		var count int
		if err := s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatal("other data was affected", table, err)
		}
	}
	if removed, err := s.PruneAuditBefore(context.Background(), 1000); err != nil || removed != 0 {
		t.Fatal("repeated cleanup", removed, err)
	}
}

func TestAuditRetentionResumesAfterPartialFailureAndHonorsCancellation(t *testing.T) {
	s := auditRetentionStore(t)
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := 0; i < 2051; i++ {
		if _, err := tx.Exec("INSERT INTO audit_events(actor,action,created_at) VALUES ('admin','old',10)"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec("INSERT INTO audit_events(actor,action,created_at) VALUES ('admin','fresh',11)"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if removed, err := s.PruneAuditBefore(canceled, 10); removed != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", removed, err)
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_second_batch BEFORE DELETE ON audit_events WHEN OLD.id=1001 BEGIN SELECT RAISE(ABORT,'test cleanup failure'); END`); err != nil {
		t.Fatal(err)
	}
	if removed, err := s.PruneAuditBefore(context.Background(), 10); removed != 1000 || err == nil {
		t.Fatal("partial progress lost", removed, err)
	}
	if _, err := s.DB.Exec("DROP TRIGGER fail_second_batch"); err != nil {
		t.Fatal(err)
	}
	if removed, err := s.PruneAuditBefore(context.Background(), 10); removed != 1051 || err != nil {
		t.Fatal("cleanup did not resume", removed, err)
	}
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM audit_events").Scan(&count); err != nil || count != 1 {
		t.Fatal("recent event lost", err, count)
	}
}
