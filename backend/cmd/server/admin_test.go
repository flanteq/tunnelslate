package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tunnelslate/internal/passwordhash"
	"tunnelslate/internal/store"
)

func TestAdminCommandOutputAndErrors(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "desk.sqlite")
	db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.DB.Close()
	var output bytes.Buffer
	if err := runAdminCommand(ctx, path, []string{"create-admin", "rescue-owner"}, &output); err != nil {
		t.Fatal(err)
	}
	const prefix = "One-time password: "
	_, value, found := strings.Cut(output.String(), prefix)
	password, _, _ := strings.Cut(value, "\n")
	if !found || len(password) != 64 || !strings.Contains(output.String(), "rescue-owner") {
		t.Fatal("missing console credentials")
	}
	var hash string
	if err := db.DB.QueryRow("SELECT password_hash FROM admins WHERE username='rescue-owner'").Scan(&hash); err != nil || passwordhash.Verify(hash, password) != nil {
		t.Fatal("wrong console password", err)
	}
	for _, tc := range []struct {
		args    []string
		message string
	}{
		{[]string{"create-admin", "RESCUE-OWNER"}, "already exists"},
		{[]string{"reset-password", "missing"}, "not found"},
		{[]string{"reset-password"}, "usage:"},
		{[]string{"create-admin", "extra", "argument"}, "usage:"},
		{[]string{"unknown"}, "usage:"},
		{nil, "usage:"},
	} {
		output.Reset()
		err := runAdminCommand(ctx, path, tc.args, &output)
		if err == nil || !strings.Contains(err.Error(), tc.message) || output.Len() != 0 {
			t.Fatal("wrong error or unexpected output", err)
		}
	}
	output.Reset()
	if err := runAdminCommand(ctx, path, []string{"reset-password", "rescue-owner"}, &output); err != nil || !strings.Contains(output.String(), "Password reset") || strings.Contains(output.String(), password) {
		t.Fatal("reset did not print new credentials", err)
	}
}

func TestAdminCommandDoesNotCreateMissingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.sqlite")
	var output bytes.Buffer
	if err := runAdminCommand(context.Background(), path, []string{"create-admin", "owner"}, &output); err == nil || output.Len() != 0 {
		t.Fatal("recovery accepted a missing database")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("recovery created a database", err)
	}
}

func TestAdminCommandResetsTOTPWithoutAnEncryptionKey(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "desk.sqlite")
	db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.DB.Close()
	// Recovery must work even if the encrypted secret can no longer be read.
	if _, err := db.DB.Exec(`INSERT INTO admins(username,password_hash,created_at) VALUES ('owner','unchanged',1);
 INSERT INTO admin_totp(admin_id,secret,generation) VALUES (1,'unreadable-without-key','generation');
 INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) VALUES ('old',1,'csrf',9999999999)`); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runAdminCommand(ctx, path, []string{"reset-totp", "OWNER"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "TOTP disabled for administrator: owner") || strings.Contains(output.String(), "One-time password:") {
		t.Fatal("incorrect TOTP reset output")
	}
	var hash string
	var count int
	if err := db.DB.QueryRow("SELECT password_hash FROM admins WHERE id=1").Scan(&hash); err != nil || hash != "unchanged" {
		t.Fatal("factor reset changed the password")
	}
	db.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&count)
	if count != 0 {
		t.Fatal("factor reset kept sessions")
	}
	for _, name := range []string{"owner", "missing"} {
		output.Reset()
		if err := runAdminCommand(ctx, path, []string{"reset-totp", name}, &output); err == nil || output.Len() != 0 {
			t.Fatal("missing factor or account accepted")
		}
	}
}
