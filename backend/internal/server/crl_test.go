package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tunnelslate/internal/pki"
)

func TestCRLMaintenanceDailyScheduleAndFailureRetry(t *testing.T) {
	h, db, _ := fixture(t)
	s := h.(*Server)
	ctx := context.Background()
	if delay := s.maintainCRL(ctx, time.Now()); delay != 24*time.Hour {
		t.Fatal("normal CRL checks must be daily", delay)
	}
	s.pki.PKIDir, s.pki.RuntimeDir = t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(s.pki.RuntimeDir, "ca.crt"), []byte("incomplete PKI"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if delay := s.maintainCRL(ctx, time.Now()); delay != 5*time.Minute {
			t.Fatal("failed CRL renewal must retry in five minutes", delay)
		}
	}
	var count int
	if err := db.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='pki.crl.expired' AND severity='CRITICAL'").Scan(&count); err != nil || count != 1 {
		t.Fatal("retries flooded or missed the journal", count, err)
	}
	if !s.crlRenewalFailed.Load() {
		t.Fatal("failure state not retained")
	}
}

func TestCRLAuditDeduplicatesFailuresAndReportsRecovery(t *testing.T) {
	h, db, _ := fixture(t)
	s := h.(*Server)
	ctx := context.Background()
	failure := errors.New("test renewal failure")
	for i := 0; i < 2; i++ {
		if err := s.auditCRL(ctx, false, failure, pki.CRLStatus{State: "renewal_due"}); err != nil {
			t.Fatal(err)
		}
	}
	// A new server instance must not repeat the same warning after restart.
	restarted, err := New(s.cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.auditCRL(ctx, false, failure, pki.CRLStatus{State: "renewal_due"}); err != nil {
		t.Fatal(err)
	}
	if err := s.auditCRL(ctx, false, failure, pki.CRLStatus{State: "expired"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.auditCRL(ctx, false, nil, pki.CRLStatus{State: "valid"}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.DB.Query("SELECT action,severity FROM audit_events ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := [][2]string{{"pki.crl.renewal_failed", "WARNING"}, {"pki.crl.expired", "CRITICAL"}, {"pki.crl.recovered", "INFO"}}
	for i := 0; rows.Next(); i++ {
		var action, severity string
		if err := rows.Scan(&action, &severity); err != nil {
			t.Fatal(err)
		}
		if i >= len(want) || [2]string{action, severity} != want[i] {
			t.Fatal("unexpected journal event", i, action, severity)
		}
		want[i] = [2]string{}
	}
	for _, remaining := range want {
		if remaining != [2]string{} {
			t.Fatal("missing journal event", remaining)
		}
	}
}
