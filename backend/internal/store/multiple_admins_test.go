package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBootstrapDoesNotRecreateDeletedBuiltinAdmin(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "desk.sqlite")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("UPDATE admins SET password_setup_required=0,bootstrap_pending=0; INSERT INTO admins(username,password_hash,created_at) VALUES ('owner','test-hash',1)"); err != nil {
		t.Fatal(err)
	}
	if err := s.CleanupInitialPassword(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) VALUES ('old',1,'csrf',9999999999); DELETE FROM admins WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM admins").Scan(&count)
	if count != 1 {
		t.Fatal("deleted administrator recreated")
	}
	s.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&count)
	if count != 0 {
		t.Fatal("deleted administrator sessions survived")
	}
	if _, err := os.Stat(s.InitialPasswordPath()); !os.IsNotExist(err) {
		t.Fatal("bootstrap file recreated", err)
	}
	if _, err := s.DB.Exec("INSERT INTO admins(username,password_hash,created_at) VALUES ('next-owner','test-hash',1)"); err != nil {
		t.Fatal(err)
	}
	var id int64
	s.DB.QueryRow("SELECT id FROM admins WHERE username='next-owner'").Scan(&id)
	if id <= 2 {
		t.Fatal("administrator ID reused", id)
	}
}
