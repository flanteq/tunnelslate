package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/*.sql
var migrations embed.FS

var ErrLegacyDatabase = errors.New("this database belongs to a pre-release test installation; a clean installation with a new data directory is required; keep the old data as a backup")

type Store struct {
	DB                  *sql.DB
	initialPasswordPath string
	// Serialize global network changes with device address validation/reservation.
	ConfigurationMu sync.Mutex
	// Serialize final public responses with link revocation/rotation. Never hold
	// this lock while waiting for PKI work or generating a profile.
	LinkMu sync.RWMutex
}

func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: path}
	db, err := sql.Open("sqlite3", u.String()+"?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000&_synchronous=FULL")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db, initialPasswordPath: filepath.Join(filepath.Dir(path), "initial_admin_password")}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	return s.migrateFiles(ctx, migrations)
}

func (s *Store) migrateFiles(ctx context.Context, source fs.FS) error {
	entries, err := fs.ReadDir(source, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	type migration struct {
		name, checksum string
		body           []byte
	}
	ordered := make([]migration, 0, len(entries))
	known := make(map[string]string, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		body, err := fs.ReadFile(source, "migrations/"+name)
		if err != nil {
			return err
		}
		checksum := fmt.Sprintf("%x", sha256.Sum256(body))
		ordered = append(ordered, migration{name, checksum, body})
		known[name] = checksum
	}
	// Inspect history before changing any application tables. The old pre-release
	// 001 has the same filename but a different schema and no recorded checksums.
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations')").Scan(&exists); err != nil {
		return err
	}
	applied := map[string]bool{}
	if exists {
		var checksums bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pragma_table_info('schema_migrations') WHERE name='checksum')").Scan(&checksums); err != nil {
			return err
		}
		if !checksums {
			return ErrLegacyDatabase
		}
		rows, err := tx.QueryContext(ctx, "SELECT name,checksum FROM schema_migrations ORDER BY name")
		if err != nil {
			return err
		}
		for rows.Next() {
			var name, checksum string
			if err = rows.Scan(&name, &checksum); err != nil {
				rows.Close()
				return err
			}
			expected, ok := known[name]
			if !ok {
				rows.Close()
				return fmt.Errorf("database migration %s is unavailable in this build; use the matching or a newer application version", name)
			}
			if checksum != expected {
				rows.Close()
				return fmt.Errorf("migration %s checksum mismatch; restore the matching application and database; do not edit migration history", name)
			}
			applied[name] = true
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	if len(applied) == 0 {
		var tables int
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND name!='schema_migrations'").Scan(&tables); err != nil {
			return err
		}
		if tables != 0 {
			return errors.New("database has application tables without a supported migration history; restore a matching backup or start with a new data directory")
		}
	}
	if !exists {
		if _, err = tx.ExecContext(ctx, "CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, checksum TEXT NOT NULL)"); err != nil {
			return err
		}
	}
	for _, migration := range ordered {
		if applied[migration.name] {
			continue
		}
		if _, err = tx.ExecContext(ctx, string(migration.body)); err == nil {
			_, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations(name,checksum) VALUES (?,?)", migration.name, migration.checksum)
		}
		if err != nil {
			return fmt.Errorf("migration %s: %w", migration.name, err)
		}
	}
	return tx.Commit()
}

func (s *Store) Audit(ctx context.Context, actor, action, target string) error {
	_, err := s.DB.ExecContext(ctx, "INSERT INTO audit_events(actor, action, target, created_at) VALUES (?,?,?,?)", actor, action, target, time.Now().Unix())
	return err
}
