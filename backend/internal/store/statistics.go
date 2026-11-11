package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"tunnelslate/internal/statswire"
)

type DeviceStatistics struct {
	ID     string           `json:"id"`
	Name   string           `json:"name"`
	Totals statswire.Totals `json:"totals"`
}
type ClientStatistics struct {
	Totals  statswire.Totals   `json:"totals"`
	Devices []DeviceStatistics `json:"devices"`
}
type DailyStatistics struct {
	Days     []statswire.Day `json:"days"`
	Total    int             `json:"total"`
	Page     int             `json:"page"`
	PageSize int             `json:"page_size"`
}

type Traffic struct {
	Received int64 `json:"bytes_received"`
	Sent     int64 `json:"bytes_sent"`
}
type ServerStatistics struct {
	statswire.Totals
	Today    Traffic `json:"today"`
	Date     string  `json:"date"`
	TimeZone string  `json:"time_zone"`
}

func delta(next, prev statswire.Totals) (statswire.Totals, error) {
	d := statswire.Totals{Sessions: next.Sessions - prev.Sessions, Duration: next.Duration - prev.Duration, Received: next.Received - prev.Received, Sent: next.Sent - prev.Sent}
	if d.Sessions < 0 || d.Duration < 0 || d.Received < 0 || d.Sent < 0 {
		return d, errors.New("statistics counters went backwards")
	}
	return d, nil
}

// ApplyStatistics commits the raw session, daily buckets, all three independent
// lifetime totals and the idempotency checkpoint in one SQLite transaction.
func (s *Store) ApplyStatistics(ctx context.Context, r statswire.Record, cutoff time.Time) (bool, error) {
	if err := r.Validate(); err != nil {
		return false, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var previous statswire.Record
	var saved string
	err = tx.QueryRowContext(ctx, "SELECT record FROM vpn_stat_checkpoints WHERE id=?", r.ID).Scan(&saved)
	if err == nil {
		if err = json.Unmarshal([]byte(saved), &previous); err != nil {
			return false, err
		}
		if previous.CommonName != r.CommonName || previous.Started != r.Started || previous.Epoch != r.Epoch {
			return false, errors.New("statistics identity changed")
		}
		if r.Observed < previous.Observed || previous.State != "active" {
			return false, nil
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	change, err := delta(r.Totals, previous.Totals)
	if err != nil {
		return false, err
	}
	if change == (statswire.Totals{}) && previous.State == r.State {
		return false, nil
	}
	var device, client string
	var deviceDeleted, clientDeleted bool
	err = tx.QueryRowContext(ctx, `SELECT d.id,d.client_id,d.deleted_at IS NOT NULL,c.deleted_at IS NOT NULL FROM devices d JOIN clients c ON c.id=d.client_id WHERE d.id=(SELECT device_id FROM certificates WHERE common_name=? UNION SELECT id FROM devices WHERE common_name=? LIMIT 1)`, r.CommonName, r.CommonName).Scan(&device, &client, &deviceDeleted, &clientDeleted)
	if err != nil {
		return false, fmt.Errorf("resolve statistics certificate: %w", err)
	}
	targets := [][2]string{{"server", ""}}
	if !clientDeleted {
		targets = append(targets, [2]string{"client", client})
	}
	if !clientDeleted && !deviceDeleted {
		targets = append(targets, [2]string{"device", device})
	}
	for _, target := range targets {
		_, err = tx.ExecContext(ctx, `INSERT INTO vpn_stat_totals(kind,entity_id,sessions,duration_seconds,bytes_received,bytes_sent) VALUES(?,?,?,?,?,?) ON CONFLICT(kind,entity_id) DO UPDATE SET sessions=sessions+excluded.sessions,duration_seconds=duration_seconds+excluded.duration_seconds,bytes_received=bytes_received+excluded.bytes_received,bytes_sent=bytes_sent+excluded.bytes_sent`, target[0], target[1], change.Sessions, change.Duration, change.Received, change.Sent)
		if err != nil {
			return false, err
		}
	}
	days := map[string]statswire.Totals{}
	for _, d := range previous.Days {
		days[d.Date] = d.Totals
	}
	for _, d := range r.Days {
		if d.Date < cutoff.UTC().Format("2006-01-02") {
			continue
		}
		v, e := delta(d.Totals, days[d.Date])
		if e != nil {
			return false, e
		}
		if v.Received == 0 && v.Sent == 0 {
			continue
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO vpn_stat_server_days(date,bytes_received,bytes_sent) VALUES(?,?,?) ON CONFLICT(date) DO UPDATE SET bytes_received=bytes_received+excluded.bytes_received,bytes_sent=bytes_sent+excluded.bytes_sent`, d.Date, v.Received, v.Sent)
		if err != nil {
			return false, err
		}
	}
	if !clientDeleted && !deviceDeleted {
		// Old records delivered after an outage still contribute to lifetime totals,
		// but they must not resurrect expired detailed history.
		if r.Ended == 0 || r.Ended >= cutoff.Unix() {
			_, err = tx.ExecContext(ctx, `INSERT INTO vpn_stat_sessions(id,device_id,started_at,observed_at,ended_at,state,duration_seconds,bytes_received,bytes_sent) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET observed_at=excluded.observed_at,ended_at=excluded.ended_at,state=excluded.state,duration_seconds=excluded.duration_seconds,bytes_received=excluded.bytes_received,bytes_sent=excluded.bytes_sent`, r.ID, device, r.Started, r.Observed, r.Ended, r.State, r.Duration, r.Received, r.Sent)
			if err != nil {
				return false, err
			}
		}
		for _, d := range r.Days {
			if d.Date < cutoff.UTC().Format("2006-01-02") {
				continue
			}
			v, e := delta(d.Totals, days[d.Date])
			if e != nil {
				return false, e
			}
			if v == (statswire.Totals{}) {
				continue
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO vpn_stat_days(device_id,date,sessions,duration_seconds,bytes_received,bytes_sent) VALUES(?,?,?,?,?,?) ON CONFLICT(device_id,date) DO UPDATE SET sessions=sessions+excluded.sessions,duration_seconds=duration_seconds+excluded.duration_seconds,bytes_received=bytes_received+excluded.bytes_received,bytes_sent=bytes_sent+excluded.bytes_sent`, device, d.Date, v.Sessions, v.Duration, v.Received, v.Sent)
			if err != nil {
				return false, err
			}
		}
	}
	data, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO vpn_stat_checkpoints(id,ended_at,record) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET ended_at=excluded.ended_at,record=excluded.record`, r.ID, r.Ended, string(data))
	if err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (s *Store) StatisticsTotals(ctx context.Context, kind, id string) (statswire.Totals, error) {
	var v statswire.Totals
	err := s.DB.QueryRowContext(ctx, `SELECT sessions,duration_seconds,bytes_received,bytes_sent FROM vpn_stat_totals WHERE kind=? AND entity_id=?`, kind, id).Scan(&v.Sessions, &v.Duration, &v.Received, &v.Sent)
	if errors.Is(err, sql.ErrNoRows) {
		return v, nil
	}
	return v, err
}

// Read both periods in a single snapshot, using the same UTC dates as collection.
// This is a direct read of independent aggregates, never a sum of device history.
func (s *Store) ServerStatistics(ctx context.Context, now time.Time) (ServerStatistics, error) {
	v := ServerStatistics{Date: now.UTC().Format("2006-01-02"), TimeZone: "UTC"}
	err := s.DB.QueryRowContext(ctx, `SELECT t.sessions,t.duration_seconds,t.bytes_received,t.bytes_sent,COALESCE(d.bytes_received,0),COALESCE(d.bytes_sent,0) FROM vpn_stat_totals t LEFT JOIN vpn_stat_server_days d ON d.date=? WHERE t.kind='server' AND t.entity_id=''`, v.Date).Scan(&v.Sessions, &v.Duration, &v.Received, &v.Sent, &v.Today.Received, &v.Today.Sent)
	return v, err
}
func (s *Store) ClientStatistics(ctx context.Context, id string) (ClientStatistics, error) {
	v := ClientStatistics{Devices: []DeviceStatistics{}}
	// One read transaction keeps the displayed client/device counters consistent.
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	var exists bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM clients WHERE id=? AND deleted_at IS NULL)", id).Scan(&exists); err != nil {
		return v, err
	}
	if !exists {
		return v, sql.ErrNoRows
	}
	err = tx.QueryRowContext(ctx, `SELECT sessions,duration_seconds,bytes_received,bytes_sent FROM vpn_stat_totals WHERE kind='client' AND entity_id=?`, id).Scan(&v.Totals.Sessions, &v.Totals.Duration, &v.Totals.Received, &v.Totals.Sent)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return v, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT d.id,d.name,COALESCE(t.sessions,0),COALESCE(t.duration_seconds,0),COALESCE(t.bytes_received,0),COALESCE(t.bytes_sent,0) FROM devices d LEFT JOIN vpn_stat_totals t ON t.kind='device' AND t.entity_id=d.id WHERE d.client_id=? AND d.deleted_at IS NULL ORDER BY d.name COLLATE NOCASE,d.id`, id)
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var d DeviceStatistics
		if err = rows.Scan(&d.ID, &d.Name, &d.Totals.Sessions, &d.Totals.Duration, &d.Totals.Received, &d.Totals.Sent); err != nil {
			rows.Close()
			return v, err
		}
		v.Devices = append(v.Devices, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return v, err
	}
	return v, tx.Commit()
}
func (s *Store) StatisticsDays(ctx context.Context, client, device string, page, size int) (DailyStatistics, error) {
	v := DailyStatistics{Days: []statswire.Day{}, Page: page, PageSize: size}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	var exists bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM devices d JOIN clients c ON c.id=d.client_id WHERE d.id=? AND d.client_id=? AND d.deleted_at IS NULL AND c.deleted_at IS NULL)`, device, client).Scan(&exists)
	if err != nil {
		return v, err
	}
	if !exists {
		return v, sql.ErrNoRows
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM vpn_stat_days WHERE device_id=?`, device).Scan(&v.Total); err != nil {
		return v, err
	}
	last := (v.Total + size - 1) / size
	if last < 1 {
		last = 1
	}
	if v.Page > last {
		v.Page = last
	}
	rows, err := tx.QueryContext(ctx, `SELECT date,sessions,duration_seconds,bytes_received,bytes_sent FROM vpn_stat_days WHERE device_id=? ORDER BY date DESC LIMIT ? OFFSET ?`, device, size, (v.Page-1)*size)
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var d statswire.Day
		if err = rows.Scan(&d.Date, &d.Sessions, &d.Duration, &d.Received, &d.Sent); err != nil {
			rows.Close()
			return v, err
		}
		v.Days = append(v.Days, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return v, err
	}
	return v, tx.Commit()
}

// PruneStatistics leaves lifetime aggregates and active session checkpoints alone.
// Pending files are checked under the same lock as the producer/consumer.
func (s *Store) PruneStatistics(ctx context.Context, cutoff time.Time, pending map[string]bool) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM vpn_stat_sessions WHERE ended_at>0 AND ended_at<?`, cutoff.Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM vpn_stat_days WHERE date<?`, cutoff.UTC().Format("2006-01-02")); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM vpn_stat_server_days WHERE date<?`, cutoff.UTC().Format("2006-01-02")); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT c.id FROM vpn_stat_checkpoints c WHERE c.ended_at>0 AND (c.ended_at<? OR NOT EXISTS(SELECT 1 FROM vpn_stat_sessions s WHERE s.id=c.id))`, cutoff.Unix())
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		if !pending[id] {
			ids = append(ids, id)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err = tx.ExecContext(ctx, "DELETE FROM vpn_stat_checkpoints WHERE id=?", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
