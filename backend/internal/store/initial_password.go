package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tunnelslate/internal/passwordhash"
)

func (s *Store) InitialPasswordPath() string { return s.initialPasswordPath }

// Bootstrap publishes the secret durably before committing its hash. An
// interrupted first start reuses the same file instead of rotating credentials.
func (s *Store) Bootstrap(ctx context.Context) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var hash string
	var required bool
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM admins").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		err = tx.QueryRowContext(ctx, "SELECT password_hash,password_setup_required FROM admins WHERE bootstrap_pending=1 AND password_setup_required=1 LIMIT 1").Scan(&hash, &required)
		if errors.Is(err, sql.ErrNoRows) {
			if err := tx.Commit(); err != nil {
				return err
			}
			return s.CleanupInitialPassword(ctx)
		}
	} else {
		err = sql.ErrNoRows
	}
	if err == nil {
		if err := tx.Commit(); err != nil {
			return err
		}
		if !required {
			if err := s.CleanupInitialPassword(ctx); err != nil {
				slog.Warn("Initial password file cleanup pending", "error", err)
			}
			return nil
		}
		password, err := readInitialPassword(s.initialPasswordPath)
		if err != nil {
			return fmt.Errorf("read initial administrator password (restore this file with its database): %w", err)
		}
		if passwordhash.Verify(hash, password) != nil {
			return errors.New("initial administrator password file does not match the database")
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		password, err := ensureInitialPassword(s.initialPasswordPath)
		if err != nil {
			return fmt.Errorf("prepare initial administrator password: %w", err)
		}
		encoded, err := passwordhash.Hash(password)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO admins(id,username,password_hash,created_at,password_setup_required,bootstrap_pending) VALUES (1,'admin',?,?,1,1)`, encoded, time.Now().Unix()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO audit_events(actor,action,created_at) VALUES ('admin', 'admin.created', ?)", time.Now().Unix()); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	} else {
		return err
	}
	slog.Info("Administrator password setup required", "password_file", s.initialPasswordPath)
	return nil
}

func readInitialPassword(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() != 65 {
		return "", errors.New("invalid initial password file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	password := strings.TrimSuffix(string(data), "\n")
	decoded, err := hex.DecodeString(password)
	if err != nil || len(decoded) != 32 {
		return "", errors.New("invalid initial password file")
	}
	return password, nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func ensureInitialPassword(path string) (string, error) {
	if password, err := readInitialPassword(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			err = syncDirectory(path)
		}
		return password, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	password := hex.EncodeToString(secret)
	file, err := os.CreateTemp(filepath.Dir(path), ".initial-password-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.WriteString(password + "\n"); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	// Publish without overwriting an initial password from another startup.
	if err := os.Link(file.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	if err := syncDirectory(path); err != nil {
		return "", err
	}
	return readInitialPassword(path)
}

// Never delete the file while setup is pending. Called after commit, at startup,
// and by the recovery worker so a temporary filesystem error remains retryable.
func (s *Store) CleanupInitialPassword(ctx context.Context) error {
	var required bool
	var count int
	err := s.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM admins WHERE bootstrap_pending=1 AND password_setup_required=1),(SELECT count(*) FROM admins)").Scan(&required, &count)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if required || count == 0 {
		return nil
	}
	if err := os.Remove(s.initialPasswordPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// A process crash between writing and publishing the file can leave a
	// temporary secret. Remove those copies as well after setup is committed.
	entries, err := os.ReadDir(filepath.Dir(s.initialPasswordPath))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".initial-password-") {
			if err := os.Remove(filepath.Join(filepath.Dir(s.initialPasswordPath), entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return syncDirectory(s.initialPasswordPath)
}
