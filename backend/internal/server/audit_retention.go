package server

import (
	"context"
	"log/slog"
	"time"
)

func (s *Server) cleanupAudit(ctx context.Context, now time.Time) (int64, error) {
	work, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cutoff := now.Unix() - int64(s.cfg.AuditRetentionDays)*86400
	removed, err := s.store.PruneAuditBefore(work, cutoff)
	if removed > 0 {
		s.events.invalidate("audit")
		slog.Info("Expired audit events deleted", "count", removed, "retention_days", s.cfg.AuditRetentionDays)
	}
	return removed, err
}

func (s *Server) runAuditRetention(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		if _, err := s.cleanupAudit(ctx, time.Now()); err != nil && ctx.Err() == nil {
			slog.Warn("Audit retention cleanup pending", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
