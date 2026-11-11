package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tunnelslate/internal/config"
	"tunnelslate/internal/statswire"
)

func TestStatisticsDurableImportAPIOwnershipAndRetention(t *testing.T) {
	h, db, _ := fixture(t)
	s := h.(*Server)
	if s.cfg.StatsRetentionDays != config.DefaultStatsRetentionDays {
		t.Fatal("wrong default")
	}
	dir := filepath.Join(t.TempDir(), "control")
	s.cfg.ManagementSocket = filepath.Join(dir, "management.sock")
	cn := "desk-0123456789abcdef0123456789abcdef"
	if _, err := db.DB.Exec(`INSERT INTO clients(id,name,created_at) VALUES('alice','Alice',0),('bob','Bob',0);INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES('laptop','alice','Laptop',?,0)`, cn); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	r := statswire.NewRecord(strings.Repeat("a", 32), strings.Repeat("b", 32), cn, now.Unix()-20)
	r.Advance(now.Unix(), 100, 200)
	queue := s.statisticsDir()
	if err := os.MkdirAll(queue, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(queue, r.ID+".json")
	if err := statswire.Write(file, r); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		changed, err := s.collectStatistics(context.Background(), now, true)
		if err != nil || changed != (i == 0) {
			t.Fatal(i, changed, err)
		}
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("active file removed", err)
	}
	if w := request(h, "GET", "/api/clients/alice/statistics", "", nil, "", ""); w.Code != http.StatusUnauthorized {
		t.Fatal("public statistics", w.Code)
	}
	cookie, _ := signIn(t, h)
	dashboard := request(h, "GET", "/api/dashboard", "", cookie, "", "")
	if dashboard.Code != 200 {
		t.Fatal(dashboard.Code, dashboard.Body.String())
	}
	var overview struct {
		Statistics struct {
			Today struct {
				Received int64 `json:"bytes_received"`
				Sent     int64 `json:"bytes_sent"`
			} `json:"today"`
			Date     string `json:"date"`
			TimeZone string `json:"time_zone"`
		} `json:"statistics"`
	}
	if err := json.Unmarshal(dashboard.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	expectedToday := statswire.Totals{}
	for _, day := range r.Days {
		if day.Date == now.UTC().Format("2006-01-02") {
			expectedToday = day.Totals
		}
	}
	if overview.Statistics.Today.Received != expectedToday.Received || overview.Statistics.Today.Sent != expectedToday.Sent || overview.Statistics.Date != now.UTC().Format("2006-01-02") || overview.Statistics.TimeZone != "UTC" {
		t.Fatal(overview)
	}
	w := request(h, "GET", "/api/clients/alice/statistics", "", cookie, "", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var v struct {
		Totals    statswire.Totals `json:"totals"`
		Retention int              `json:"retention_days"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Totals != r.Totals || v.Retention != 90 {
		t.Fatal(v)
	}
	for path, code := range map[string]int{"/api/clients/bob/statistics/devices/laptop/days": 404, "/api/clients/alice/statistics/devices/laptop/days?page=0": 400, "/api/clients/alice/statistics/devices/laptop/days?page_size=1000": 400, "/api/clients/alice/statistics/devices/laptop/days?page=999&page_size=10": 200, "/api/clients/missing/statistics": 404} {
		if w = request(h, "GET", path, "", cookie, "", ""); w.Code != code {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	r.State = "completed"
	r.Ended = r.Observed
	if err := statswire.Write(file, r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.collectStatistics(context.Background(), now, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("terminal record not acknowledged", err)
	}
	// Replay after commit and before acknowledgement is harmless.
	if err := statswire.Write(file, r); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.collectStatistics(context.Background(), now, false); err != nil || changed {
		t.Fatal("double count", changed, err)
	}
	if _, err := s.collectStatistics(context.Background(), now.AddDate(0, 0, 91), true); err != nil {
		t.Fatal(err)
	}
	var count int
	db.DB.QueryRow("SELECT count(*) FROM vpn_stat_sessions").Scan(&count)
	if count != 0 {
		t.Fatal("history retained")
	}
	totals, err := db.StatisticsTotals(context.Background(), "server", "")
	if err != nil || totals != r.Totals {
		t.Fatal("lifetime lost", totals, err)
	}
}
