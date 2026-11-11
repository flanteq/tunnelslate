package pki

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"tunnelslate/internal/store"
)

func emptyService(t *testing.T) *Service {
	t.Helper()
	if _, err := os.Stat("/usr/share/easy-rsa/easyrsa"); err != nil {
		t.Skip("run in the backend-test Docker image")
	}
	root := t.TempDir()
	s := &Service{PKIDir: filepath.Join(root, "pki"), RuntimeDir: filepath.Join(root, "openvpn")}
	for _, dir := range []string{s.PKIDir, s.RuntimeDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := store.Open(context.Background(), filepath.Join(root, "desk.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.DB.Close() })
	s.Store = db
	return s
}

func TestBootstrapOnlyOnRequestAndNeverReplacesCA(t *testing.T) {
	s := emptyService(t)
	ctx := context.Background()
	if err := s.PrepareExisting(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.path("ca.crt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("startup created a CA")
	}
	status, err := s.InitializationStatus(ctx)
	if err != nil || status.State != "empty" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	// Simultaneous clicks must create exactly one CA.
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Go(func() { errs <- s.Initialize(ctx, "admin") })
	}
	wg.Wait()
	close(errs)
	successes, conflicts := 0, 0
	for err := range errs {
		var problem *Error
		if err == nil {
			successes++
		} else if errors.As(err, &problem) && problem.Code == 409 {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("success=%d conflict=%d", successes, conflicts)
	}
	ca, caPEM, err := readCert(s.path("ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if !ca.IsCA || ca.Subject.CommonName != "TunnelSlate-CA" {
		t.Fatal("invalid CA")
	}
	server, _, err := readCert(s.path("issued", "server.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := server.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatal(err)
	}
	keyPath := s.path("private", "desk-tls-crypt.key")
	tlsKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateTLSKey(tlsKey); err != nil {
		t.Fatal(err)
	}
	// Simulate the original scaffold: TLS key exists only in runtime.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	// Preserve custom server directives and repair missing runtime files on restart.
	config := []byte("dev tun\n# custom setting survives\n")
	if err := os.WriteFile(filepath.Join(s.RuntimeDir, "server.conf"), config, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.RuntimeDir, "server.crt")); err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareExisting(ctx); err != nil {
		t.Fatal(err)
	}
	for path, expected := range map[string][]byte{s.path("ca.crt"): caPEM, keyPath: tlsKey, filepath.Join(s.RuntimeDir, "server.conf"): config} {
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("existing file changed: %s err=%v", path, err)
		}
	}
	status, err = s.InitializationStatus(ctx)
	if err != nil || status.State != "ready" || !s.Available() {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestIncompletePKIIsNotReset(t *testing.T) {
	s := emptyService(t)
	ctx := context.Background()
	if err := os.Mkdir(s.root(), 0700); err != nil {
		t.Fatal(err)
	}
	path := s.path("ca.crt")
	original := []byte("incomplete installation: preserve this data\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Initialize(ctx, "admin"); err == nil {
		t.Fatal("incomplete installation silently reset")
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, original) {
		t.Fatal("original CA overwritten")
	}
	if s.Available() {
		t.Fatal("incomplete PKI reported ready")
	}
	if _, err := os.Stat(filepath.Join(s.RuntimeDir, ".desk-ready")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("readiness marker published despite failure")
	}
	status, err := s.InitializationStatus(ctx)
	if err != nil || status.State != "failed" || status.Error == "" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestInvalidTLSKeyRejected(t *testing.T) {
	if validateTLSKey([]byte("invalid")) == nil {
		t.Fatal("invalid TLS key accepted")
	}
}
