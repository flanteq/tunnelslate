package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tunnelslate/internal/passwordhash"

	"golang.org/x/crypto/bcrypt"
)

func TestInitialPasswordSurvivesInterruptedBootstrapAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "desk.sqlite")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	// Fail after the file is published, before the account transaction commits.
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_bootstrap BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'test'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(ctx); err == nil {
		t.Fatal("expected audit failure")
	}
	if err := s.CleanupInitialPassword(ctx); err != nil {
		t.Fatal(err)
	}
	password, err := readInitialPassword(s.InitialPasswordPath())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.InitialPasswordPath())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("password file permissions: %v %v", info, err)
	}
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM admins").Scan(&count); err != nil || count != 0 {
		t.Fatalf("bootstrap did not roll back: %v", err)
	}
	if _, err := s.DB.Exec("DROP TRIGGER fail_bootstrap"); err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	var username, hash string
	var required bool
	if err := s.DB.QueryRow("SELECT username,password_hash,password_setup_required FROM admins").Scan(&username, &hash, &required); err != nil {
		t.Fatal(err)
	}
	if username != "admin" || !required || passwordhash.Verify(hash, password) != nil {
		t.Fatal("restart changed bootstrap account")
	}
	if err := s.CleanupInitialPassword(ctx); err != nil {
		t.Fatal(err)
	}
	if again, err := readInitialPassword(s.InitialPasswordPath()); err != nil || again != password {
		t.Fatal("pending setup lost its password")
	}
	if _, err := s.DB.Exec("UPDATE admins SET password_setup_required=0"); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(filepath.Dir(path), ".initial-password-interrupted")
	if err := os.WriteFile(stale, []byte(password), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("interrupted publication left a secret copy")
	}
	if _, err := os.Stat(s.InitialPasswordPath()); !os.IsNotExist(err) {
		t.Fatal("completed setup kept the file")
	}
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.InitialPasswordPath()); !os.IsNotExist(err) {
		t.Fatal("restart regenerated the password")
	}
}

func TestReopenPreservesPermanentAccountAndSession(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "desk.sqlite")
	existing, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { existing.DB.Close() })
	hash, err := bcrypt.GenerateFromPassword([]byte("existing-administrator-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = existing.DB.Exec("INSERT INTO admins(id,username,password_hash,created_at) VALUES (1,'operator',?,1)", string(hash)); err != nil {
		t.Fatal(err)
	}
	if _, err = existing.DB.Exec("INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) VALUES ('session',1,'csrf',9999999999)"); err != nil {
		t.Fatal(err)
	}
	if err = existing.DB.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if err = s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	var username, saved string
	var required bool
	if err = s.DB.QueryRow("SELECT username,password_hash,password_setup_required FROM admins").Scan(&username, &saved, &required); err != nil || required || username != "operator" || saved != string(hash) {
		t.Fatal("reopen modified existing credentials", err)
	}
	var sessions int
	if err = s.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&sessions); err != nil || sessions != 1 {
		t.Fatal("reopen revoked an existing session", err)
	}
	if _, err = os.Stat(s.InitialPasswordPath()); !os.IsNotExist(err) {
		t.Fatal("reopen created an initial password")
	}
}

func TestInitialPasswordRejectsInvalidFileAndDoesNotRotateMissingSecret(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "desk.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if err := os.WriteFile(s.InitialPasswordPath(), []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(ctx); err == nil {
		t.Fatal("invalid file accepted")
	}
	if err := os.Remove(s.InitialPasswordPath()); err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	var previousHash string
	if err := s.DB.QueryRow("SELECT password_hash FROM admins").Scan(&previousHash); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.InitialPasswordPath()); err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(ctx); err == nil {
		t.Fatal("missing secret silently replaced")
	}
	var hash string
	if err := s.DB.QueryRow("SELECT password_hash FROM admins").Scan(&hash); err != nil || hash != previousHash {
		t.Fatal("missing file changed credentials")
	}
	if err := os.WriteFile(s.InitialPasswordPath(), []byte(strings.Repeat("0", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(ctx); err == nil {
		t.Fatal("mismatched password file accepted")
	}
}
