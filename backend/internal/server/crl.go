package server

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"tunnelslate/internal/pki"
)

const crlCheckInterval = 24 * time.Hour
const crlRetryInterval = 5 * time.Minute

func (s *Server) crlStatus(now time.Time) pki.CRLStatus {
	status := s.pki.CRLStatus(now)
	if status.State == "renewal_due" && s.crlRenewalFailed.Load() {
		status.State = "renewal_failed"
	}
	return status
}

// The audit journal also deduplicates repeated failures across app restarts.
func (s *Server) auditCRL(ctx context.Context, renewed bool, failure error, status pki.CRLStatus) error {
	var previous, previousSeverity string
	err := s.store.DB.QueryRowContext(ctx, `SELECT action,severity FROM audit_events
	 WHERE actor='system' AND action IN ('pki.crl.renew','pki.crl.renewal_failed','pki.crl.expired','pki.crl.recovered')
	 ORDER BY id DESC LIMIT 1`).Scan(&previous, &previousSeverity)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	action, severity := "", "INFO"
	if failure != nil {
		action, severity = "pki.crl.renewal_failed", "WARNING"
		if status.State == "expired" || status.State == "missing" || status.State == "invalid" {
			action, severity = "pki.crl.expired", "CRITICAL"
		}
		if previous == action && previousSeverity == severity {
			return nil
		}
	} else if renewed {
		action = "pki.crl.renew"
	} else if status.State == "valid" && (previous == "pki.crl.renewal_failed" || previous == "pki.crl.expired") {
		action = "pki.crl.recovered"
	}
	if action == "" {
		return nil
	}
	_, err = s.store.DB.ExecContext(ctx, "INSERT INTO audit_events(actor,action,target,severity,created_at) VALUES ('system',?,'crl',?,?)", action, severity, time.Now().Unix())
	if err == nil {
		s.invalidate("audit")
	}
	return err
}

func (s *Server) maintainCRL(ctx context.Context, now time.Time) time.Duration {
	work, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	renewed, err := s.pki.MaintainCRL(work, now)
	if ctx.Err() != nil {
		return crlRetryInterval
	}
	s.crlRenewalFailed.Store(err != nil)
	status := s.crlStatus(time.Now())
	auditCtx, auditCancel := context.WithTimeout(ctx, 3*time.Second)
	defer auditCancel()
	if auditErr := s.auditCRL(auditCtx, renewed, err, status); auditErr != nil {
		slog.Warn("CRL maintenance audit pending", "error", auditErr)
	}
	// Refresh the shared sample and SSE even if only the failure flag changed.
	select {
	case s.liveKick <- struct{}{}:
	default:
	}
	if err != nil {
		slog.Warn("CRL renewal pending", "error", err)
		return crlRetryInterval
	}
	if renewed {
		slog.Info("CRL renewed", "next_update", status.NextUpdate)
	}
	return crlCheckInterval
}
