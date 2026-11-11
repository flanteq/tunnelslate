package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tunnelslate/internal/passwordhash"
)

func recoveryStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "desk.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	return s
}

func TestConsoleAdminRecoveryCreatesAndResetsOnlyTarget(t *testing.T) {
	ctx := context.Background()
	s := recoveryStore(t)
	created, err := s.RecoverAdmin(ctx, "Owner", true)
	if err != nil || created.Username != "Owner" || len(created.TemporaryPassword) != 64 {
		t.Fatal("create credentials missing", err)
	}
	if _, err := s.DB.Exec(`INSERT INTO admins(username,password_hash,created_at) VALUES ('other','untouched',1);
 INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) SELECT 'owner-session',id,'csrf',9999999999 FROM admins WHERE username='Owner';
 INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) SELECT 'other-session',id,'csrf',9999999999 FROM admins WHERE username='other'`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		create bool
		want   error
	}{{"owner", true, ErrAdminExists}, {"missing", false, ErrAdminNotFound}} {
		credentials, err := s.RecoverAdmin(ctx, tc.name, tc.create)
		if !errors.Is(err, tc.want) || credentials != (AdminCredentials{}) {
			t.Fatal("expected a clear error without credentials", err)
		}
	}
	var hash string
	var required, pending bool
	if err := s.DB.QueryRow("SELECT password_hash,password_setup_required,bootstrap_pending FROM admins WHERE username='Owner'").Scan(&hash, &required, &pending); err != nil {
		t.Fatal(err)
	}
	if hash == created.TemporaryPassword || strings.Contains(hash, created.TemporaryPassword) || passwordhash.Verify(hash, created.TemporaryPassword) != nil || !required || pending {
		t.Fatal("creation or rejected duplicate changed credentials incorrectly")
	}
	reset, err := s.RecoverAdmin(ctx, "OWNER", false)
	if err != nil || reset.Username != "Owner" || reset.TemporaryPassword == created.TemporaryPassword {
		t.Fatal("reset credentials missing", err)
	}
	if err := s.DB.QueryRow("SELECT password_hash,password_setup_required,bootstrap_pending FROM admins WHERE username='Owner'").Scan(&hash, &required, &pending); err != nil {
		t.Fatal(err)
	}
	if passwordhash.Verify(hash, created.TemporaryPassword) == nil || passwordhash.Verify(hash, reset.TemporaryPassword) != nil || !required || pending {
		t.Fatal("reset did not replace credentials and require setup")
	}
	var sessions, others, audits int
	s.DB.QueryRow("SELECT count(*) FROM sessions WHERE token_hash='owner-session'").Scan(&sessions)
	s.DB.QueryRow("SELECT count(*) FROM sessions WHERE token_hash='other-session'").Scan(&others)
	s.DB.QueryRow("SELECT count(*) FROM audit_events WHERE actor='system:console' AND target='Owner' AND action IN ('admin.created','admin.password.reset')").Scan(&audits)
	if sessions != 0 || others != 1 || audits != 2 {
		t.Fatal("wrong session isolation or audit history", sessions, others, audits)
	}
}

func TestConsoleResetRecoversLostBootstrapFileAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	s := recoveryStore(t)
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.InitialPasswordPath()); err != nil {
		t.Fatal(err)
	}
	reset, err := s.RecoverAdmin(ctx, "admin", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal("recovery still depends on bootstrap file", err)
	}
	if _, err := os.Stat(s.InitialPasswordPath()); !os.IsNotExist(err) {
		t.Fatal("bootstrap file recreated", err)
	}
	var hash string
	if err := s.DB.QueryRow("SELECT password_hash FROM admins WHERE username='admin'").Scan(&hash); err != nil || passwordhash.Verify(hash, reset.TemporaryPassword) != nil {
		t.Fatal("restart changed recovery password", err)
	}
}

func TestConsoleRecoveryRollsBackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	s := recoveryStore(t)
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	initial, err := os.ReadFile(s.InitialPasswordPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) VALUES ('old',1,'csrf',9999999999);
 CREATE TRIGGER fail_console_audit BEFORE INSERT ON audit_events WHEN NEW.actor='system:console' BEGIN SELECT RAISE(ABORT,'test audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		create bool
	}{{"admin", false}, {"new-owner", true}} {
		credentials, err := s.RecoverAdmin(ctx, tc.name, tc.create)
		if err == nil || credentials != (AdminCredentials{}) {
			t.Fatal("audit failure exposed uncommitted credentials")
		}
	}
	var hash string
	var sessions, count int
	var pending bool
	s.DB.QueryRow("SELECT password_hash,bootstrap_pending FROM admins WHERE id=1").Scan(&hash, &pending)
	s.DB.QueryRow("SELECT count(*) FROM admins").Scan(&count)
	s.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&sessions)
	if passwordhash.Verify(hash, strings.TrimSpace(string(initial))) != nil || !pending || count != 1 || sessions != 1 {
		t.Fatal("failed recovery changed credentials or sessions")
	}
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal("failed recovery invalidated initial password", err)
	}
}

func TestConsoleAdminUsernameRules(t *testing.T) {
	s := recoveryStore(t)
	for _, name := range []string{"", "ab", "-owner", "some user", "админ", strings.Repeat("x", 65), "system", "SYSTEM"} {
		if _, err := s.RecoverAdmin(context.Background(), name, true); err == nil {
			t.Fatalf("invalid username accepted: %q", name)
		}
	}
	if name, err := NormalizeAdminUsername(" Owner.Name-1_2 "); err != nil || name != "Owner.Name-1_2" {
		t.Fatal("valid username rejected", err)
	}
}
