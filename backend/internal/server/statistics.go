package server

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"tunnelslate/internal/statswire"
)

func (s *Server) statisticsDir() string {
	if s.cfg.ManagementSocket == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.cfg.ManagementSocket), "statistics")
}
func (s *Server) collectStatistics(ctx context.Context, now time.Time, prune bool) (bool, error) {
	dir := s.statisticsDir()
	if dir == "" {
		return false, nil
	}
	names, err := statswire.Records(dir)
	if err != nil {
		return false, err
	}
	changed := false
	var failures error
	cutoff := now.AddDate(0, 0, -s.cfg.StatsRetentionDays)
	for _, name := range names {
		if ctx.Err() != nil {
			return changed, ctx.Err()
		}
		err = statswire.Locked(dir, func() error {
			var r statswire.Record
			if err := statswire.Read(filepath.Join(dir, name), &r); os.IsNotExist(err) {
				return nil
			} else if err != nil {
				return err
			}
			if r.ID+".json" != name {
				return errors.New("statistics filename mismatch")
			}
			updated, err := s.store.ApplyStatistics(ctx, r, cutoff)
			if err != nil {
				return err
			}
			changed = changed || updated
			if r.State != "active" {
				if err = statswire.Write(statswire.Acknowledgement(dir, r.ID), r.ID); err != nil {
					return err
				}
				if err = os.Remove(filepath.Join(dir, name)); err != nil {
					return err
				}
				return statswire.SyncDir(dir)
			}
			return nil
		})
		if err != nil {
			failures = errors.Join(failures, err)
		}
	}
	if prune {
		err = statswire.Locked(dir, func() error {
			names, err := statswire.Records(dir)
			if err != nil {
				return err
			}
			pending := map[string]bool{}
			for _, name := range names {
				pending[strings.TrimSuffix(name, ".json")] = true
			}
			return s.store.PruneStatistics(ctx, cutoff, pending)
		})
	}
	return changed, errors.Join(failures, err)
}
func (s *Server) runStatistics(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var nextPrune time.Time
	var lastDay string
	failed := false
	for {
		now := time.Now()
		prune := !now.Before(nextPrune)
		work, cancel := context.WithTimeout(ctx, 20*time.Second)
		changed, err := s.collectStatistics(work, now, prune)
		if err == nil {
			s.statisticsAt.Store(time.Now().Unix())
		}
		cancel()
		if changed || prune {
			s.events.invalidate("dashboard", "statistics")
		} else if lastDay != now.UTC().Format("2006-01-02") {
			// Even an idle server must stop showing yesterday's traffic after UTC
			// midnight, without waiting for a new connection or a page reload.
			s.events.invalidate("dashboard")
		}
		lastDay = now.UTC().Format("2006-01-02")
		if err != nil && ctx.Err() == nil {
			if !failed {
				slog.Warn("VPN statistics collection pending", "error", err)
			}
			failed = true
		} else {
			failed = false
			if prune {
				nextPrune = now.Add(24 * time.Hour)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *Server) clientStatistics(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ClientStatistics(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		apiError(w, 404, "Client not found")
		return
	}
	if err != nil {
		internalError(w, "read client statistics", err)
		return
	}
	jsonResponse(w, 200, map[string]any{"totals": v.Totals, "devices": v.Devices, "retention_days": s.cfg.StatsRetentionDays})
}
func (s *Server) deviceStatisticsDays(w http.ResponseWriter, r *http.Request) {
	page, size := 1, 10
	for key, target := range map[string]*int{"page": &page, "page_size": &size} {
		if raw := r.URL.Query().Get(key); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 1000000 {
				apiError(w, 400, "Invalid statistics pagination")
				return
			}
			*target = n
		}
	}
	if size != 10 && size != 25 && size != 50 {
		apiError(w, 400, "Invalid statistics page size")
		return
	}
	v, err := s.store.StatisticsDays(r.Context(), r.PathValue("id"), r.PathValue("device"), page, size)
	if errors.Is(err, sql.ErrNoRows) {
		apiError(w, 404, "Device not found")
		return
	}
	if err != nil {
		internalError(w, "read daily statistics", err)
		return
	}
	jsonResponse(w, 200, v)
}
