package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrTOTPNotEnabled = errors.New("TOTP is not configured")

// ResetAdminTOTP intentionally needs no encryption key: it also recovers access
// when that key is lost. Password recovery alone never disables a second factor.
func (s *Store) ResetAdminTOTP(ctx context.Context, username string) (string, error) {
	name, err := NormalizeAdminUsername(username)
	if err != nil {
		return "", err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var id int64
	var configured bool
	err = tx.QueryRowContext(ctx, `SELECT id,username,EXISTS(SELECT 1 FROM admin_totp t WHERE t.admin_id=a.id)
 OR EXISTS(SELECT 1 FROM admin_totp_setups p WHERE p.admin_id=a.id) FROM admins a WHERE username=?`, name).Scan(&id, &name, &configured)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: %q", ErrAdminNotFound, name)
	}
	if err != nil {
		return "", err
	}
	if !configured {
		return "", fmt.Errorf("%w: %q", ErrTOTPNotEnabled, name)
	}
	for _, query := range []string{
		"DELETE FROM admin_totp WHERE admin_id=?",
		"DELETE FROM admin_totp_setups WHERE admin_id=?",
		"DELETE FROM admin_login_challenges WHERE admin_id=?",
		"DELETE FROM admin_totp_attempts WHERE admin_id=?",
		"DELETE FROM sessions WHERE admin_id=?",
	} {
		if _, err := tx.ExecContext(ctx, query, id); err != nil {
			return "", err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(actor,action,target,created_at) VALUES ('system:console','admin.totp.reset',?,?)`, name, time.Now().Unix()); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return name, nil
}
