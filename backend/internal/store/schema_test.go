package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestInitialSchemaAndSeedsSurviveReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "desk.sqlite")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	var integrity string
	if err = s.DB.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatal("invalid initial database", integrity, err)
	}
	rows, err := s.DB.Query("PRAGMA foreign_key_check")
	if err != nil {
		t.Fatal(err)
	}
	invalidFK := rows.Next()
	rows.Close()
	if invalidFK {
		t.Fatal("initial foreign keys invalid")
	}
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.DB.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&count); err != nil || count != len(entries) {
		t.Fatal("migration history missing", count, err)
	}
	for _, entry := range entries {
		body, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var checksum string
		if err = s.DB.QueryRow("SELECT checksum FROM schema_migrations WHERE name=?", entry.Name()).Scan(&checksum); err != nil || checksum != fmt.Sprintf("%x", sha256.Sum256(body)) {
			t.Fatal("migration checksum missing", entry.Name(), err)
		}
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE name IN ('admins_new','sessions_new','device_vpn_auth')").Scan(&count); err != nil || count != 0 {
		t.Fatal("obsolete test storage retained", err)
	}
	p, err := s.PanelSettings(ctx)
	if err != nil || p.MetricsEnabled || p.MetricsMTLS || p.InstanceName != "" || p.Revision != 1 {
		t.Fatal("incorrect initial panel settings", err)
	}
	if _, err = s.DB.Exec(`UPDATE vpn_stat_totals SET bytes_received=123 WHERE kind='server';UPDATE panel_settings SET instance_name='Saved';UPDATE monitoring_counters SET value=7 WHERE scope='panel'`); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	var bytes, failures int64
	var name string
	if err = reopened.DB.QueryRow(`SELECT (SELECT bytes_received FROM vpn_stat_totals WHERE kind='server'),(SELECT value FROM monitoring_counters WHERE scope='panel'),(SELECT instance_name FROM panel_settings)`).Scan(&bytes, &failures, &name); err != nil || bytes != 123 || failures != 7 || name != "Saved" {
		t.Fatal("reopen reset singleton rows", err)
	}
}

func TestInitialSchemaActiveNamesAndOperationConstraints(t *testing.T) {
	s := auditRetentionStore(t)
	for _, stmt := range []string{
		`INSERT INTO admins(username,password_hash,created_at) VALUES('Owner','hash',0)`,
		`INSERT INTO clients(id,name,created_at) VALUES('client','Existing client',0)`,
		`INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES('device','client','Laptop','cn-old',0)`,
		`INSERT INTO operations(id,kind,state,step,device_id,client_id,created_at,updated_at) VALUES('operation','rotate','partial','disconnect_sessions','device','client',0,0)`,
	} {
		if _, err := s.DB.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	for _, stmt := range []string{
		`INSERT INTO admins(username,password_hash,created_at) VALUES('owner','hash',0)`,
		`INSERT INTO clients(id,name,created_at) VALUES('duplicate','existing CLIENT',0)`,
		`INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES('duplicate','client','LAPTOP','cn-other',0)`,
		`INSERT INTO operations(id,kind,state,step,device_id,created_at,updated_at) VALUES('another','revoke','pending','','device',0,0)`,
		`INSERT INTO audit_events(actor,action,created_at,severity) VALUES('admin','test',0,'INVALID')`,
	} {
		if _, err := s.DB.Exec(stmt); err == nil {
			t.Fatal("constraint not enforced", stmt)
		}
	}
	if _, err := s.DB.Exec(`UPDATE devices SET deleted_at=1 WHERE id='device';INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES('replacement','client','LAPTOP','cn-new',0);UPDATE clients SET deleted_at=1 WHERE id='client';INSERT INTO clients(id,name,created_at) VALUES('replacement','existing CLIENT',0)`); err != nil {
		t.Fatal("archived names cannot be reused", err)
	}
}

func TestLegacyPreReleaseDatabaseRejectedWithoutChangingData(t *testing.T) {
	for _, last := range []string{"001_initial.sql", "019_panel_settings.sql"} {
		t.Run(last, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "desk.sqlite")
			legacy, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatal(err)
			}
			defer legacy.Close()
			if _, err = legacy.Exec(`CREATE TABLE schema_migrations(name TEXT PRIMARY KEY);CREATE TABLE admins(id INTEGER PRIMARY KEY,username TEXT NOT NULL);INSERT INTO admins VALUES(1,'saved-owner');INSERT INTO schema_migrations VALUES('001_initial.sql')`); err != nil {
				t.Fatal(err)
			}
			if last != "001_initial.sql" {
				if _, err = legacy.Exec("INSERT INTO schema_migrations VALUES(?)", last); err != nil {
					t.Fatal(err)
				}
			}
			if s, err := Open(context.Background(), path); !errors.Is(err, ErrLegacyDatabase) {
				if s != nil {
					s.DB.Close()
				}
				t.Fatal("old schema accepted or unclear error", err)
			}
			var name string
			if err = legacy.QueryRow("SELECT username FROM admins WHERE id=1").Scan(&name); err != nil || name != "saved-owner" {
				t.Fatal("legacy data changed", err)
			}
			var changed bool
			if err = legacy.QueryRow("SELECT EXISTS(SELECT 1 FROM pragma_table_info('schema_migrations') WHERE name='checksum')").Scan(&changed); err != nil || changed {
				t.Fatal("legacy history modified", err)
			}
			if err = legacy.QueryRow("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='panel_settings')").Scan(&changed); err != nil || changed {
				t.Fatal("legacy schema partially initialized", err)
			}
		})
	}
}

func TestUnknownOrModifiedMigrationHistoryRejected(t *testing.T) {
	for _, kind := range []string{"checksum", "newer", "missing"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "desk.sqlite")
			s, err := Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.DB.Close()
			if _, err = s.DB.Exec("UPDATE panel_settings SET instance_name='Retained'"); err != nil {
				t.Fatal(err)
			}
			statement := map[string]string{"checksum": "UPDATE schema_migrations SET checksum='modified'", "newer": "INSERT INTO schema_migrations VALUES('999_future.sql','future')", "missing": "DROP TABLE schema_migrations"}[kind]
			if _, err = s.DB.Exec(statement); err != nil {
				t.Fatal(err)
			}
			other, err := Open(context.Background(), path)
			if other != nil {
				other.DB.Close()
			}
			message := map[string]string{"checksum": "checksum mismatch", "newer": "unavailable in this build", "missing": "without a supported migration history"}[kind]
			if err == nil || !strings.Contains(err.Error(), message) {
				t.Fatal("unexpected history accepted", kind, err)
			}
			var name string
			if err = s.DB.QueryRow("SELECT instance_name FROM panel_settings").Scan(&name); err != nil || name != "Retained" {
				t.Fatal("rejected history changed data", err)
			}
		})
	}
}

func TestFutureMigrationsAreAtomicOrderedAndIdempotent(t *testing.T) {
	s := auditRetentionStore(t)
	ctx := context.Background()
	initial, err := migrations.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	files := fstest.MapFS{
		"migrations/001_initial.sql": {Data: initial},
		"migrations/002_future.sql":  {Data: []byte("CREATE TABLE future_note(value TEXT NOT NULL);INSERT INTO future_note VALUES('once');")},
		"migrations/003_failure.sql": {Data: []byte("CREATE TABLE failed_note(value TEXT);INSERT INTO missing_table VALUES(1);")},
	}
	if err = s.migrateFiles(ctx, files); err == nil {
		t.Fatal("bad migration accepted")
	}
	var count int
	if err = s.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE name IN ('future_note','failed_note')").Scan(&count); err != nil || count != 0 {
		t.Fatal("partial migration survived rollback", err)
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&count); err != nil || count != 1 {
		t.Fatal("failed migration marked as applied", err)
	}
	delete(files, "migrations/003_failure.sql")
	for range 2 {
		if err = s.migrateFiles(ctx, files); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM future_note").Scan(&count); err != nil || count != 1 {
		t.Fatal("migration ran more than once", err)
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&count); err != nil || count != 2 {
		t.Fatal("future migration not recorded", err)
	}
}

func TestFailedInitialMigrationLeavesDatabaseEmpty(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "desk.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Store{DB: db}
	files := fstest.MapFS{"migrations/001_initial.sql": {Data: []byte("CREATE TABLE incomplete(id INTEGER);INSERT INTO nonexistent VALUES(1);")}}
	if err = s.migrateFiles(context.Background(), files); err == nil {
		t.Fatal("invalid initial migration accepted")
	}
	var count int
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&count); err != nil || count != 0 {
		t.Fatal("incomplete initial schema survived rollback", err)
	}
}
