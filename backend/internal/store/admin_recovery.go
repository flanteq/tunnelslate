package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"tunnelslate/internal/passwordhash"
)

var (
	ErrAdminExists           = errors.New("administrator already exists")
	ErrAdminNotFound         = errors.New("administrator not found")
	ErrAdminUsernameReserved = errors.New(`the username "system" is reserved`)
	ErrAdminUsernameInvalid  = errors.New("username must be 3–64 characters: Latin letters, digits, dots, hyphens or underscores; start with a letter or digit")
	adminUsername            = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}$`)
)

// NormalizeAdminUsername keeps console and web account creation rules identical.
func NormalizeAdminUsername(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "system") {
		return "", ErrAdminUsernameReserved
	}
	if !adminUsername.MatchString(value) {
		return "", ErrAdminUsernameInvalid
	}
	return value, nil
}

type AdminCredentials struct {
	Username          string
	TemporaryPassword string
}

// RecoverAdmin changes credentials directly in the shared database, without a
// web session. Only the console receives the plaintext secret, after commit.
func (s *Store) RecoverAdmin(ctx context.Context, username string, create bool) (AdminCredentials, error) {
	name, err := NormalizeAdminUsername(username)
	if err != nil {
		return AdminCredentials{}, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return AdminCredentials{}, err
	}
	password := hex.EncodeToString(secret)
	hash, err := passwordhash.Hash(password)
	if err != nil {
		return AdminCredentials{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return AdminCredentials{}, err
	}
	defer tx.Rollback()
	var id int64
	action := "admin.password.reset"
	if create {
		action = "admin.created"
		err = tx.QueryRowContext(ctx, `INSERT INTO admins(username,password_hash,created_at,password_setup_required)
 VALUES (?,?,?,1) ON CONFLICT(username) DO NOTHING RETURNING id,username`, name, hash, time.Now().Unix()).Scan(&id, &name)
		if errors.Is(err, sql.ErrNoRows) {
			return AdminCredentials{}, fmt.Errorf("%w: %q", ErrAdminExists, name)
		}
	} else {
		err = tx.QueryRowContext(ctx, `UPDATE admins SET password_hash=?,password_setup_required=1,bootstrap_pending=0
 WHERE username=? RETURNING id,username`, hash, name).Scan(&id, &name)
		if errors.Is(err, sql.ErrNoRows) {
			return AdminCredentials{}, fmt.Errorf("%w: %q", ErrAdminNotFound, name)
		}
	}
	if err != nil {
		return AdminCredentials{}, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE admin_id=?", id); err != nil {
		return AdminCredentials{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(actor,action,target,created_at) VALUES ('system:console',?,?,?)`, action, name, time.Now().Unix()); err != nil {
		return AdminCredentials{}, err
	}
	if err := tx.Commit(); err != nil {
		return AdminCredentials{}, err
	}
	// A bootstrap reset replaces the file-based password too. Cleanup failures
	// must not hide a committed password; the server retries this cleanup.
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.CleanupInitialPassword(cleanup); err != nil {
		slog.Warn("Initial password file cleanup pending", "error", err)
	}
	return AdminCredentials{Username: name, TemporaryPassword: password}, nil
}
