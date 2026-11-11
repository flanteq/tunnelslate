package store

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestTOTPSecretsEncryptedBoundToAccountAndDurable(t *testing.T) {
	ctx := context.Background()
	s := recoveryStore(t)
	if _, err := os.Stat(s.TOTPKeyPath()); !os.IsNotExist(err) {
		t.Fatal("TOTP key created before setup", err)
	}
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	encoded, err := s.SealTOTPSecret(ctx, 1, secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, secret) {
		t.Fatal("secret stored in plaintext")
	}
	info, err := os.Stat(s.TOTPKeyPath())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("insecure key permissions", err)
	}
	opened, err := s.OpenTOTPSecret(1, encoded)
	if err != nil || opened != secret {
		t.Fatal("secret did not decrypt", err)
	}
	if _, err := s.OpenTOTPSecret(2, encoded); err == nil {
		t.Fatal("secret can be moved to another account")
	}
	bytes, _ := base64.RawStdEncoding.DecodeString(encoded)
	bytes[len(bytes)-1] ^= 1
	if _, err := s.OpenTOTPSecret(1, base64.RawStdEncoding.EncodeToString(bytes)); err == nil {
		t.Fatal("modified ciphertext accepted")
	}
	other, err := s.SealTOTPSecret(ctx, 1, secret)
	if err != nil || other == encoded {
		t.Fatal("encryption reused a nonce", err)
	}
	var path string
	if err := s.DB.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	if opened, err := reopened.OpenTOTPSecret(1, encoded); err != nil || opened != secret {
		t.Fatal("key did not survive reopening", err)
	}
}

func TestMissingTOTPKeyFailsClosedAndConsoleCanRecover(t *testing.T) {
	ctx := context.Background()
	s := recoveryStore(t)
	if _, err := s.DB.Exec("INSERT INTO admins(username,password_hash,created_at) VALUES ('owner','unchanged-password',1),('other','other-password',1)"); err != nil {
		t.Fatal(err)
	}
	encoded, err := s.SealTOTPSecret(ctx, 1, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO admin_totp(admin_id,secret,generation) VALUES (1,?,'generation');
 INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) VALUES ('own',1,'csrf',9999999999),('other',2,'csrf',9999999999);
 INSERT INTO admin_login_challenges(token_hash,admin_id,password_hash,generation,expires_at) VALUES ('challenge',1,'unchanged-password','generation',9999999999)`, encoded); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.TOTPKeyPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenTOTPSecret(1, encoded); err == nil {
		t.Fatal("missing key ignored")
	}
	if _, err := s.SealTOTPSecret(ctx, 2, "NEWSECRET"); err == nil {
		t.Fatal("missing key replaced while encrypted data exists")
	}
	if _, err := os.Stat(s.TOTPKeyPath()); !os.IsNotExist(err) {
		t.Fatal("missing key silently recreated")
	}
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_totp_reset BEFORE INSERT ON audit_events WHEN NEW.action='admin.totp.reset' BEGIN SELECT RAISE(ABORT,'test audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResetAdminTOTP(ctx, "owner"); err == nil {
		t.Fatal("reset ignored audit failure")
	}
	var factors int
	s.DB.QueryRow("SELECT count(*) FROM admin_totp").Scan(&factors)
	if factors != 1 {
		t.Fatal("failed reset changed TOTP")
	}
	if _, err := s.DB.Exec("DROP TRIGGER fail_totp_reset"); err != nil {
		t.Fatal(err)
	}
	if name, err := s.ResetAdminTOTP(ctx, "OWNER"); err != nil || name != "owner" {
		t.Fatal("console could not recover without key", err)
	}
	var sessions, challenges, audits int
	var password string
	s.DB.QueryRow("SELECT count(*) FROM sessions WHERE admin_id=1").Scan(&sessions)
	s.DB.QueryRow("SELECT count(*) FROM admin_login_challenges").Scan(&challenges)
	s.DB.QueryRow("SELECT count(*) FROM audit_events WHERE actor='system:console' AND action='admin.totp.reset'").Scan(&audits)
	s.DB.QueryRow("SELECT password_hash FROM admins WHERE id=1").Scan(&password)
	if sessions != 0 || challenges != 0 || audits != 1 || password != "unchanged-password" {
		t.Fatal("incorrect reset isolation")
	}
	s.DB.QueryRow("SELECT count(*) FROM sessions WHERE admin_id=2").Scan(&sessions)
	if sessions != 1 {
		t.Fatal("reset ended another administrator's session")
	}
	if _, err := s.ResetAdminTOTP(ctx, "owner"); !errors.Is(err, ErrTOTPNotEnabled) {
		t.Fatal("missing TOTP error", err)
	}
	if _, err := s.ResetAdminTOTP(ctx, "missing"); !errors.Is(err, ErrAdminNotFound) {
		t.Fatal("missing administrator error", err)
	}
	if _, err := s.SealTOTPSecret(ctx, 1, "NEWSECRET"); err != nil {
		t.Fatal("new key cannot be created after clearing all factors", err)
	}
}
