package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tunnelslate/internal/statswire"
)

func TestServerDailyTrafficUTCReplayDeletionAndRetention(t *testing.T) {
	s := statisticsStore(t)
	r := statRecord()
	r.Advance(r.Started+20, 1000, 2000)
	applyStat(t, s, r)
	applyStat(t, s, r)
	ctx := context.Background()
	read := func(at int64) ServerStatistics {
		t.Helper()
		v, err := s.ServerStatistics(ctx, time.Unix(at, 0).In(time.FixedZone("Office", 3*3600)))
		if err != nil {
			t.Fatal(err)
		}
		if v.TimeZone != "UTC" {
			t.Fatal(v)
		}
		return v
	}
	before := read(r.Started)
	after := read(r.Observed)
	if before.Date != "2026-11-10" || before.Today != (Traffic{Received: 500, Sent: 1000}) || after.Date != "2026-11-11" || after.Today != before.Today || after.Totals != r.Totals {
		t.Fatal(before, after)
	}
	// Deleting all devices must not subtract their traffic from today's server row.
	if _, err := s.DB.Exec("UPDATE devices SET deleted_at=1 WHERE client_id='client';UPDATE clients SET deleted_at=1 WHERE id='client'"); err != nil {
		t.Fatal(err)
	}
	if v := read(r.Observed); v.Today != after.Today {
		t.Fatal("deleted server traffic", v)
	}
	r.Advance(r.Observed+10, 1300, 2600)
	applyStat(t, s, r)
	applyStat(t, s, r)
	if v := read(r.Observed); v.Today != (Traffic{Received: 800, Sent: 1600}) || v.Totals != r.Totals {
		t.Fatal("post-deletion accounting", v)
	}
	if v := read(r.Observed + 86400); v.Today != (Traffic{}) || v.Totals != r.Totals {
		t.Fatal("yesterday displayed as today", v)
	}
	// A daily write failure must roll back the lifetime updates and checkpoint too.
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_server_day BEFORE UPDATE ON vpn_stat_server_days BEGIN SELECT RAISE(ABORT,'test'); END`); err != nil {
		t.Fatal(err)
	}
	future := r
	future.Days = append([]statswire.Day(nil), r.Days...)
	future.Advance(r.Observed+10, 1500, 3000)
	if _, err := s.ApplyStatistics(ctx, future, time.Unix(0, 0)); err == nil {
		t.Fatal("expected daily failure")
	}
	if v := read(r.Observed); v.Totals != r.Totals || v.Today.Received != 800 {
		t.Fatal("partial commit", v)
	}
	if _, err := s.DB.Exec("DROP TRIGGER fail_server_day"); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Unix(r.Observed+86400, 0)
	if err := s.PruneStatistics(ctx, cutoff, nil); err != nil {
		t.Fatal(err)
	}
	if v := read(r.Observed); v.Today != (Traffic{}) || v.Totals != r.Totals {
		t.Fatal("wrong retention", v)
	}
}

func TestServerDailyReopenPreservesCheckpointsWithoutDoubleCounting(t *testing.T) {
	s := statisticsStore(t)
	r := statRecord()
	r.Advance(r.Started+20, 1000, 2000)
	applyStat(t, s, r)
	if _, err := s.DB.Exec(`UPDATE devices SET deleted_at=1 WHERE id='device'`); err != nil {
		t.Fatal(err)
	}
	var path string
	rows, err := s.DB.Query("PRAGMA database_list")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var seq int
		var name, file string
		if err = rows.Scan(&seq, &name, &file); err != nil {
			t.Fatal(err)
		}
		if name == "main" {
			path = file
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if path == "" || !filepath.IsAbs(path) {
		t.Fatal("missing database path")
	}
	if err = s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	check := func(rx, tx int64) {
		t.Helper()
		v, err := reopened.ServerStatistics(context.Background(), time.Unix(r.Observed, 0))
		if err != nil || v.Today != (Traffic{Received: rx, Sent: tx}) {
			t.Fatal(v, err)
		}
	}
	check(500, 1000)
	applyStat(t, reopened, r)
	check(500, 1000)
	r.Advance(r.Observed+10, 1400, 2800)
	applyStat(t, reopened, r)
	check(900, 1800)
}

const statisticsCN = "desk-0123456789abcdef0123456789abcdef"

func statisticsStore(t *testing.T) *Store {
	s := auditRetentionStore(t)
	_, err := s.DB.Exec(`INSERT INTO clients(id,name,created_at) VALUES('client','Alice',0),('other','Bob',0);
 INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES('device','client','Laptop','legacy',0),('phone','client','Phone','phone',0);
 INSERT INTO certificates(serial,device_id,status,not_before,not_after,common_name) VALUES('serial','device','valid',0,9999999999,'desk-0123456789abcdef0123456789abcdef');`)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func statRecord() statswire.Record {
	return statswire.NewRecord(strings.Repeat("a", 32), strings.Repeat("b", 32), statisticsCN, time.Date(2026, 11, 10, 23, 59, 50, 0, time.UTC).Unix())
}
func applyStat(t *testing.T, s *Store, r statswire.Record) {
	t.Helper()
	if _, err := s.ApplyStatistics(context.Background(), r, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
}
func total(t *testing.T, s *Store, kind, id string) statswire.Totals {
	t.Helper()
	v, err := s.StatisticsTotals(context.Background(), kind, id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestStatisticsExactlyOnceDailyBucketsAndRetention(t *testing.T) {
	s := statisticsStore(t)
	r := statRecord()
	r.Advance(r.Started+20, 1000, 2000)
	applyStat(t, s, r)
	applyStat(t, s, r)
	expected := r.Totals
	for _, target := range [][2]string{{"server", ""}, {"client", "client"}, {"device", "device"}} {
		if got := total(t, s, target[0], target[1]); got != expected {
			t.Fatal(target, got, expected)
		}
	}
	stale := statRecord()
	stale.Advance(stale.Started+10, 500, 1000)
	if changed, err := s.ApplyStatistics(context.Background(), stale, time.Unix(0, 0)); err != nil || changed {
		t.Fatal("stale replay", changed, err)
	}
	days, err := s.StatisticsDays(context.Background(), "client", "device", 1, 10)
	if err != nil || days.Total != 2 || days.Days[0].Duration != 10 || days.Days[1].Sessions != 1 {
		t.Fatal(days, err)
	}
	r.Advance(r.Observed+10, 1500, 3000)
	r.State = "completed"
	r.Ended = r.Observed
	applyStat(t, s, r)
	applyStat(t, s, r)
	if got := total(t, s, "server", ""); got != r.Totals {
		t.Fatal(got, r.Totals)
	}
	// A failed aggregate update must roll back every table, including checkpoints.
	if _, err = s.DB.Exec(`CREATE TRIGGER stats_fail BEFORE INSERT ON vpn_stat_totals WHEN NEW.kind='device' BEGIN SELECT RAISE(ABORT,'test'); END;`); err != nil {
		t.Fatal(err)
	}
	next := statRecord()
	next.ID = strings.Repeat("c", 32)
	next.Advance(next.Started+1, 1, 2)
	if _, err = s.ApplyStatistics(context.Background(), next, time.Unix(0, 0)); err == nil {
		t.Fatal("expected transaction failure")
	}
	if got := total(t, s, "server", ""); got != r.Totals {
		t.Fatal("partially committed", got)
	}
	if _, err = s.DB.Exec("DROP TRIGGER stats_fail"); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Unix(r.Ended+86400, 0)
	if err = s.PruneStatistics(context.Background(), cutoff, map[string]bool{r.ID: true}); err != nil {
		t.Fatal(err)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM vpn_stat_checkpoints").Scan(&count)
	if count != 1 {
		t.Fatal("pending replay checkpoint pruned")
	}
	if got := total(t, s, "device", "device"); got != r.Totals {
		t.Fatal("lifetime lost", got)
	}
	if err = s.PruneStatistics(context.Background(), cutoff, nil); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"vpn_stat_sessions", "vpn_stat_days", "vpn_stat_checkpoints"} {
		s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&count)
		if count != 0 {
			t.Fatal("history not pruned", table, count)
		}
	}
}
func TestStatisticsDeletionDoesNotSubtractParentTotalsOrResurrectHistory(t *testing.T) {
	s := statisticsStore(t)
	r := statRecord()
	r.Advance(r.Started+10, 100, 200)
	applyStat(t, s, r)
	if _, err := s.DB.Exec("UPDATE devices SET deleted_at=1 WHERE id='device'"); err != nil {
		t.Fatal(err)
	}
	r.Advance(r.Started+20, 200, 400)
	applyStat(t, s, r)
	if got := total(t, s, "device", "device"); got != (statswire.Totals{}) {
		t.Fatal("deleted device resurrected", got)
	}
	if got := total(t, s, "client", "client"); got != r.Totals {
		t.Fatal("client total lost", got)
	}
	if _, err := s.DB.Exec("UPDATE clients SET deleted_at=2 WHERE id='client'"); err != nil {
		t.Fatal(err)
	}
	r.Advance(r.Started+30, 300, 600)
	r.State = "completed"
	r.Ended = r.Observed
	applyStat(t, s, r)
	if got := total(t, s, "client", "client"); got != (statswire.Totals{}) {
		t.Fatal("deleted client resurrected", got)
	}
	if got := total(t, s, "server", ""); got != r.Totals {
		t.Fatal("server lost deleted client", got)
	}
	var n int
	s.DB.QueryRow("SELECT count(*) FROM vpn_stat_sessions").Scan(&n)
	if n != 0 {
		t.Fatal("deleted history resurrected")
	}
}
func TestStatisticsLateDeliveryActiveRetentionAndDeviceOwnership(t *testing.T) {
	s := statisticsStore(t)
	r := statRecord()
	r.Advance(r.Started+86400*100, 100, 200)
	cutoff := time.Unix(r.Observed-86400*90, 0)
	if _, err := s.ApplyStatistics(context.Background(), r, cutoff); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneStatistics(context.Background(), cutoff, nil); err != nil {
		t.Fatal(err)
	}
	var n int
	s.DB.QueryRow("SELECT count(*) FROM vpn_stat_sessions").Scan(&n)
	if n != 1 {
		t.Fatal("active session pruned")
	}
	if _, err := s.StatisticsDays(context.Background(), "other", "device", 1, 10); err == nil {
		t.Fatal("wrong client allowed")
	}
	r.State = "completed"
	r.Ended = r.Observed
	applyStat(t, s, r)
	// An entirely old session still contributes to all-time totals, without details.
	old := statRecord()
	old.ID = strings.Repeat("d", 32)
	old.Advance(old.Started+1, 9, 8)
	old.State = "completed"
	old.Ended = old.Observed
	if _, err := s.ApplyStatistics(context.Background(), old, cutoff); err != nil {
		t.Fatal(err)
	}
	s.DB.QueryRow("SELECT count(*) FROM vpn_stat_sessions").Scan(&n)
	if n != 1 {
		t.Fatal("expired detail resurrected")
	}
	if got := total(t, s, "server", ""); got.Sessions != 2 || got.Received != 109 {
		t.Fatal(got)
	}
}
