package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func signedRuntimeCRL(t *testing.T, s *Service, next time.Time, serials ...string) []byte {
	t.Helper()
	ca, _, err := readCert(s.path("ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(s.path("ca.crt"), s.path("private", "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.RevocationList{Number: big.NewInt(100), ThisUpdate: time.Now().Add(-48 * time.Hour), NextUpdate: next}
	for _, serial := range serials {
		number, ok := new(big.Int).SetString(serial, 16)
		if !ok {
			t.Fatal("bad test serial")
		}
		template.RevokedCertificateEntries = append(template.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: number, RevocationTime: time.Now().Add(-24 * time.Hour)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, ca, pair.PrivateKey.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	if err := atomicWrite(filepath.Join(s.RuntimeDir, "crl.pem"), b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCRLMaintenancePreservesRevocationsKeysAndConnections(t *testing.T) {
	s, m := serviceFixture(t)
	ctx := context.Background()
	issued, err := s.Start(ctx, "admin", "crl-issued-client-001", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(ctx, "admin", "crl-revoked-client-01", "revoke", issued.ResultSerial, ""); err != nil {
		t.Fatal(err)
	}
	active, err := s.Start(ctx, "admin", "crl-active-client-01", "issue", "client", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	_, args, err := s.operation(ctx, active.ID)
	if err != nil {
		t.Fatal(err)
	}
	m.connect(args.CN)
	ca, _ := os.ReadFile(s.path("ca.crt"))
	key, _ := os.ReadFile(s.path("private", args.CN+".key"))
	now := time.Now().Truncate(time.Second)
	if renewed, err := s.MaintainCRL(ctx, now); renewed || err != nil {
		t.Fatal("fresh CRL regenerated", renewed, err)
	}
	signedRuntimeCRL(t, s, now.Add(-time.Hour), issued.ResultSerial)
	if status := s.CRLStatus(now); status.State != "expired" {
		t.Fatal(status)
	}
	var group sync.WaitGroup
	var mu sync.Mutex
	renewals := 0
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			renewed, err := s.MaintainCRL(ctx, now)
			if err != nil {
				t.Error(err)
			}
			if renewed {
				mu.Lock()
				renewals++
				mu.Unlock()
			}
		}()
	}
	group.Wait()
	if renewals != 1 {
		t.Fatal("concurrent maintenance did not coalesce", renewals)
	}
	checkCRL(t, s, issued.ResultSerial)
	status := s.CRLStatus(time.Now())
	if status.State != "valid" || time.Until(time.Unix(status.NextUpdate, 0)) < 179*24*time.Hour {
		t.Fatal(status)
	}
	newCA, _ := os.ReadFile(s.path("ca.crt"))
	newKey, _ := os.ReadFile(s.path("private", args.CN+".key"))
	if !bytes.Equal(ca, newCA) || !bytes.Equal(key, newKey) {
		t.Fatal("renewal replaced existing credentials")
	}
	m.mu.Lock()
	connected := m.active[args.CN]
	m.mu.Unlock()
	if !connected {
		t.Fatal("ordinary CRL renewal disconnected an active client")
	}
	resumed := &Service{Store: s.Store, PKIDir: s.PKIDir, RuntimeDir: s.RuntimeDir}
	if renewed, err := resumed.MaintainCRL(ctx, now); renewed || err != nil {
		t.Fatal("restart regenerated a fresh CRL", renewed, err)
	}
}

func TestCRLMaintenanceThresholdRepairsAndCancellation(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	for _, tc := range []struct {
		until time.Time
		want  bool
	}{
		{now.Add(crlRenewBefore + time.Second), false},
		{now.Add(crlRenewBefore), true},
	} {
		signedRuntimeCRL(t, s, tc.until)
		if renewed, err := s.MaintainCRL(ctx, now); renewed != tc.want || err != nil {
			t.Fatal("renewal threshold", renewed, err)
		}
	}
	path := filepath.Join(s.RuntimeDir, "crl.pem")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if s.CRLStatus(now).State != "missing" {
		t.Fatal("missing CRL not reported")
	}
	if renewed, err := s.MaintainCRL(ctx, now); !renewed || err != nil {
		t.Fatal("missing CRL repair", renewed, err)
	}
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if s.CRLStatus(now).State != "invalid" {
		t.Fatal("invalid CRL not reported")
	}
	if renewed, err := s.MaintainCRL(ctx, now); !renewed || err != nil {
		t.Fatal("invalid CRL repair", renewed, err)
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	_, err = s.MaintainCRL(wait, now)
	unlock()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("maintenance did not honor lock timeout", err)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := s.MaintainCRL(canceled, now); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCRLMaintenanceRejectsLostRevocationsAndRetries(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	issued, err := s.Start(ctx, "admin", "crl-loss-issued-0001", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Start(ctx, "admin", "crl-loss-revoked-001", "revoke", issued.ResultSerial, ""); err != nil {
		t.Fatal(err)
	}
	indexPath := s.path("index.txt")
	index, _ := os.ReadFile(indexPath)
	// Simulate a stale restored PKI index while the signed runtime CRL remembers the revocation.
	lines := strings.Split(string(index), "\n")
	for i, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) >= 6 && fields[0] == "R" {
			fields[0], fields[2] = "V", ""
			lines[i] = strings.Join(fields, "\t")
		}
	}
	if err := os.WriteFile(indexPath, []byte(strings.Join(lines, "\n")), 0600); err != nil {
		t.Fatal(err)
	}
	previous := signedRuntimeCRL(t, s, time.Now().Add(24*time.Hour), issued.ResultSerial)
	if renewed, err := s.MaintainCRL(ctx, time.Now()); renewed || err == nil || !strings.Contains(err.Error(), "revoked serial missing") {
		t.Fatal("a published revocation was lost", renewed, err)
	}
	after, _ := os.ReadFile(filepath.Join(s.RuntimeDir, "crl.pem"))
	if !bytes.Equal(previous, after) {
		t.Fatal("failed generation overwrote the published CRL")
	}
	if err := os.WriteFile(indexPath, index, 0600); err != nil {
		t.Fatal(err)
	}
	if renewed, err := s.MaintainCRL(ctx, time.Now()); !renewed || err != nil {
		t.Fatal("renewal did not recover", renewed, err)
	}
	checkCRL(t, s, issued.ResultSerial)
}

func TestCRLMaintenanceDoesNotInitializeEmptyPKI(t *testing.T) {
	s := emptyService(t)
	if renewed, err := s.MaintainCRL(context.Background(), time.Now()); renewed || err != nil {
		t.Fatal(renewed, err)
	}
	if _, err := os.Stat(s.path("ca.crt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("maintenance initialized a CA", err)
	}
	if s.CRLStatus(time.Now()).State != "not_initialized" {
		t.Fatal("empty installation status")
	}
}
