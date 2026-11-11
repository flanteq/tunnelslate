// Package metricsweb owns an independent, optional Prometheus listener.
package metricsweb

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Enabled, MTLS                    bool
	Source, Cert, Key, CA, Directory string
}
type Prepared struct {
	Config
	TLS         *tls.Config
	fingerprint [32]byte
	Expires     int64
}
type Status struct {
	State              string `json:"state"`
	Error              string `json:"error,omitempty"`
	Address            string `json:"address"`
	CertificateExpires int64  `json:"certificate_expires,omitempty"`
}

func material(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("metrics.files")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128*1024 {
		return "", errors.New("metrics.files")
	}
	b, err := io.ReadAll(io.LimitReader(f, 128*1024+1))
	if err != nil || len(b) > 128*1024 {
		return "", errors.New("metrics.files")
	}
	return string(b), nil
}

// Prepare never opens a socket. Invalid TLS settings cannot enable plaintext.
func Prepare(c Config) (p Prepared, err error) {
	p.Config = c
	if strings.Contains(c.Cert, "PRIVATE KEY") || strings.Contains(c.CA, "PRIVATE KEY") {
		return p, errors.New("metrics.certificate_only")
	}
	if c.Source != "files" && c.Source != "pem" {
		return p, errors.New("metrics.source")
	}
	if !c.Enabled {
		return p, nil
	}
	if !c.MTLS {
		p.fingerprint = sha256.Sum256([]byte("http"))
		return p, nil
	}
	if c.Source == "files" {
		if c.Cert, err = material(filepath.Join(c.Directory, "server.crt")); err != nil {
			return p, err
		}
		if c.Key, err = material(filepath.Join(c.Directory, "server.key")); err != nil {
			return p, err
		}
		if c.CA, err = material(filepath.Join(c.Directory, "client-ca.crt")); err != nil {
			return p, err
		}
	}
	if strings.Contains(c.Cert, "PRIVATE KEY") || strings.Contains(c.CA, "PRIVATE KEY") {
		return p, errors.New("metrics.certificate_only")
	}
	pair, err := tls.X509KeyPair([]byte(c.Cert), []byte(c.Key))
	if err != nil {
		return p, errors.New("metrics.key_pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return p, errors.New("metrics.key_pair")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || len(leaf.DNSNames)+len(leaf.IPAddresses) == 0 {
		return p, errors.New("metrics.server_certificate")
	}
	validUsage := len(leaf.ExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
			validUsage = true
		}
	}
	if !validUsage {
		return p, errors.New("metrics.server_certificate")
	}
	pool := x509.NewCertPool()
	remaining := []byte(c.CA)
	count := 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return p, errors.New("metrics.client_ca")
		}
		remaining = rest
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil || block.Type != "CERTIFICATE" || !cert.IsCA || !cert.BasicConstraintsValid || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return p, errors.New("metrics.client_ca")
		}
		pool.AddCert(cert)
		count++
	}
	if count == 0 {
		return p, errors.New("metrics.client_ca")
	}
	p.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{pair}, SessionTicketsDisabled: true}
	p.Expires = leaf.NotAfter.Unix()
	p.fingerprint = sha256.Sum256([]byte(c.Cert + "\x00" + c.Key + "\x00" + c.CA))
	return p, nil
}

type Manager struct {
	mu          sync.Mutex
	address     string
	handler     http.Handler
	server      *http.Server
	fingerprint [32]byte
	status      Status
	closed      bool
}

func New(address string, h http.Handler) *Manager {
	return &Manager{address: address, handler: h, status: Status{State: "disabled", Address: address}}
}
func (m *Manager) Status() Status { m.mu.Lock(); defer m.mu.Unlock(); return m.status }
func (m *Manager) Failure(code string, requireTLS bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if requireTLS && m.server != nil && m.server.TLSConfig == nil {
		m.server.Close()
		m.server = nil
	}
	m.status.State = "error"
	m.status.Error = code
}
func (m *Manager) Apply(p Prepared) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("metrics.closed")
	}
	if !p.Enabled {
		if m.server != nil {
			m.server.Close()
			m.server = nil
		}
		m.status = Status{State: "disabled", Address: m.address}
		return nil
	}
	if m.server != nil && m.fingerprint == p.fingerprint {
		m.status.State = "running"
		m.status.Error = ""
		return nil
	}
	// Close keep-alive connections too: a former CA must not retain access after rotation.
	if m.server != nil {
		m.server.Close()
		m.server = nil
	}
	listener, err := net.Listen("tcp", m.address)
	if err != nil {
		m.status = Status{State: "error", Address: m.address, Error: "metrics.listen"}
		return errors.New("metrics.listen")
	}
	srv := &http.Server{Handler: m.handler, TLSConfig: p.TLS, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024, ErrorLog: log.New(io.Discard, "", 0)}
	m.server = srv
	m.fingerprint = p.fingerprint
	m.status = Status{State: "running", Address: listener.Addr().String(), CertificateExpires: p.Expires}
	go func() {
		var err error
		if p.TLS != nil {
			err = srv.ServeTLS(listener, "", "")
		} else {
			err = srv.Serve(listener)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.mu.Lock()
			if m.server == srv {
				m.server = nil
				m.status.State = "error"
				m.status.Error = "metrics.listen"
			}
			m.mu.Unlock()
		}
	}()
	return nil
}
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.server != nil {
		m.server.Close()
		m.server = nil
	}
}
