package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSessionMetadataSurvivesReopenAndAdminDeletionCascades(t *testing.T) {
	path := filepath.Join(t.TempDir(), "desk.sqlite")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	if _, err = s.DB.Exec(`INSERT INTO admins(username,password_hash,created_at) VALUES('owner','hash',123),('second','hash',124);
 INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at,created_at,ip_address) VALUES('retained',1,'csrf',9999999999,123,'192.0.2.10'),('other',2,'csrf2',9999999999,124,'192.0.2.11')`); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	var name, csrf, ip string
	var created, expires int64
	if err = reopened.DB.QueryRow(`SELECT a.username,p.csrf_token,p.expires_at,p.created_at,p.ip_address FROM sessions p JOIN admins a ON a.id=p.admin_id WHERE p.token_hash='retained'`).Scan(&name, &csrf, &expires, &created, &ip); err != nil {
		t.Fatal(err)
	}
	if name != "owner" || csrf != "csrf" || expires != 9999999999 || created != 123 || ip != "192.0.2.10" {
		t.Fatal("reopen changed existing session")
	}
	if _, err = reopened.DB.Exec("DELETE FROM admins WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = reopened.DB.QueryRow("SELECT count(*) FROM sessions WHERE admin_id=1").Scan(&n); err != nil || n != 0 {
		t.Fatal("deleted administrator retained sessions", err)
	}
	if err = reopened.DB.QueryRow("SELECT count(*) FROM sessions WHERE admin_id=2").Scan(&n); err != nil || n != 1 {
		t.Fatal("other administrator lost session", err)
	}
}
