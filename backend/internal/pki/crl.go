package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const crlLifetimeDays = 180
const crlRenewBefore = 30 * 24 * time.Hour

type CRLStatus struct {
	State      string `json:"state"`
	ThisUpdate int64  `json:"this_update,omitempty"`
	NextUpdate int64  `json:"next_update,omitempty"`
}

func readCRL(path string, ca *x509.Certificate) (*x509.RevocationList, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "X509 CRL" {
		return nil, fmt.Errorf("invalid CRL PEM")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		return nil, err
	}
	if !crl.NextUpdate.After(crl.ThisUpdate) {
		return nil, fmt.Errorf("invalid CRL validity period")
	}
	return crl, nil
}

// CRLStatus reads only atomically published files; it does not generate a CRL.
func (s *Service) CRLStatus(now time.Time) CRLStatus {
	status := CRLStatus{State: "not_initialized"}
	if s.PKIDir == "" || s.RuntimeDir == "" {
		return status
	}
	if empty, err := s.emptyInstallation(); err == nil && empty {
		return status
	}
	status.State = "invalid"
	ca, _, err := readCert(s.path("ca.crt"))
	if err != nil || now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return status
	}
	crl, err := readCRL(filepath.Join(s.RuntimeDir, "crl.pem"), ca)
	if errors.Is(err, os.ErrNotExist) {
		status.State = "missing"
		return status
	}
	if err != nil {
		return status
	}
	status.ThisUpdate, status.NextUpdate = crl.ThisUpdate.Unix(), crl.NextUpdate.Unix()
	switch {
	case crl.ThisUpdate.After(now.Add(time.Minute)):
		status.State = "invalid"
	case !crl.NextUpdate.After(now):
		status.State = "expired"
	case !crl.NextUpdate.After(now.Add(crlRenewBefore)):
		status.State = "renewal_due"
	default:
		status.State = "valid"
	}
	return status
}

// MaintainCRL shares the lock with issuance/revocation and rechecks after waiting.
// The PKI index remains authoritative; a missing CRL never creates a new CA.
func (s *Service) MaintainCRL(ctx context.Context, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.PKIDir == "" || s.RuntimeDir == "" {
		return false, nil
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()
	status := s.CRLStatus(now)
	if status.State == "not_initialized" {
		return false, nil
	}
	if !s.Available() {
		return false, fmt.Errorf("existing PKI is incomplete; CRL renewal requires repair")
	}
	if status.State == "valid" {
		return false, nil
	}
	if err := s.publishCRL(ctx, nil); err != nil {
		return false, err
	}
	s.notify("dashboard")
	return true, nil
}
