package server

import (
	"context"
	"testing"
	"time"

	"tunnelslate/internal/config"
)

func TestAuditRetentionConfiguredCutoffAndSSEInvalidation(t *testing.T) {
	h, db, _ := fixture(t)
	s := h.(*Server)
	if s.cfg.AuditRetentionDays != config.DefaultAuditRetentionDays {
		t.Fatal("missing default retention")
	}
	s.cfg.AuditRetentionDays = 7
	now := time.Now().Truncate(time.Second)
	cutoff := now.Unix() - 7*86400
	for _, stamp := range []int64{cutoff - 1, cutoff, cutoff + 1, now.Unix() + 86400} {
		if _, err := db.DB.Exec("INSERT INTO audit_events(actor,action,created_at) VALUES ('admin','test',?)", stamp); err != nil {
			t.Fatal(err)
		}
	}
	before := s.events.snapshot()["audit"]
	if count, err := s.cleanupAudit(context.Background(), now); err != nil || count != 2 {
		t.Fatal("wrong retention cutoff", count, err)
	}
	after := s.events.snapshot()["audit"]
	if after <= before {
		t.Fatal("cleanup did not notify open audit/overview pages")
	}
	if count, err := s.cleanupAudit(context.Background(), now); err != nil || count != 0 {
		t.Fatal("repeated cleanup", count, err)
	}
	if s.events.snapshot()["audit"] != after {
		t.Fatal("empty cleanup triggered unnecessary API refresh")
	}
	s.cfg.AuditRetentionDays = 1
	if count, err := s.cleanupAudit(context.Background(), now); err != nil || count != 1 {
		t.Fatal("shorter configured retention ignored", count, err)
	}
}

func TestAuditRetentionRunsImmediatelyAndStopsOnShutdown(t *testing.T) {
	h, db, _ := fixture(t)
	s := h.(*Server)
	if _, err := db.DB.Exec("INSERT INTO audit_events(actor,action,created_at) VALUES ('admin','old',0)"); err != nil {
		t.Fatal(err)
	}
	reader := s.events.subscribe("test")
	defer s.events.unsubscribe(reader)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); s.runAuditRetention(ctx) }()
	select {
	case <-reader.wake:
	case <-time.After(3 * time.Second):
		t.Fatal("startup cleanup did not run")
	}
	var count int
	if err := db.DB.QueryRow("SELECT count(*) FROM audit_events").Scan(&count); err != nil || count != 0 {
		t.Fatal("startup did not remove expired records", count, err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("retention worker did not stop")
	}
}
