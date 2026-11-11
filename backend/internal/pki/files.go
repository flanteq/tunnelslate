package pki

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"tunnelslate/internal/management"
)

// Keep names recognizable while avoiding path separators, control characters
// and reserved filename punctuation. Limit UTF-8 bytes, not only rune count.
func profileFilename(client, device string, expires time.Time) string {
	part := func(value, fallback string) string {
		var b strings.Builder
		separator := false
		for _, r := range value {
			if unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r) || r == '_' {
				if separator && b.Len() > 0 {
					b.WriteByte('-')
				}
				if b.Len()+len(string(r)) > 80 {
					break
				}
				b.WriteRune(r)
				separator = false
			} else {
				separator = true
			}
		}
		result := strings.Trim(b.String(), "-_")
		if result == "" {
			return fallback
		}
		return result
	}
	return part(client, "client") + "-" + part(device, "device") + "-" + expires.UTC().Format("20060102") + ".ovpn"
}

func id() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func Serial(serial *big.Int) string { return strings.ToUpper(serial.Text(16)) }
func (s *Service) root() string     { return filepath.Join(s.PKIDir, "easyrsa") }
func (s *Service) path(parts ...string) string {
	return filepath.Join(append([]string{s.root()}, parts...)...)
}

func (s *Service) lock(ctx context.Context) (func(), error) {
	if s.PKIDir == "" {
		return nil, fmt.Errorf("PKI directory is not configured")
	}
	f, err := os.OpenFile(filepath.Join(s.PKIDir, ".desk.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (s *Service) run(ctx context.Context, program string, args ...string) error {
	return s.runEnv(ctx, nil, program, args...)
}

func (s *Service) runEnv(ctx context.Context, env []string, program string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Env = append(os.Environ(), "EASYRSA_PKI="+s.root(), "EASYRSA_BATCH=1", "EASYRSA_ALGO=ec", "EASYRSA_CURVE=prime256v1", "EASYRSA_DIGEST=sha256", "EASYRSA_CRL_DAYS="+strconv.Itoa(crlLifetimeDays))
	cmd.Env = append(cmd.Env, env...)
	// No shell, passwords, or command output (which may include private material) in logs/API.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s failed: %w", filepath.Base(program), args[0], err)
	}
	return nil
}
func (s *Service) easy(ctx context.Context, args ...string) error {
	return s.run(ctx, "/usr/share/easy-rsa/easyrsa", args...)
}

func readCert(path string) (*x509.Certificate, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	return cert, b, err
}

func (s *Service) Available() bool {
	if s.PKIDir == "" {
		return false
	}
	for _, path := range []string{s.path("ca.crt"), s.path("private", "ca.key"), s.path("issued", "server.crt"), s.path("private", "server.key"), filepath.Join(s.RuntimeDir, ".desk-ready"), filepath.Join(s.RuntimeDir, "tls-crypt.key")} {
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			return false
		}
	}
	return true
}

func (s *Service) issue(ctx context.Context, cn string, expiresAt int64) (*x509.Certificate, error) {
	if !management.ValidCN(cn) {
		return nil, fmt.Errorf("invalid certificate name")
	}
	certPath, keyPath, reqPath := s.path("issued", cn+".crt"), s.path("private", cn+".key"), s.path("reqs", cn+".req")
	exists := func(path string) bool { _, err := os.Stat(path); return err == nil }
	if !exists(certPath) {
		if !exists(reqPath) {
			if exists(keyPath) {
				// Resume a crash between key generation and CSR publication without replacing the key.
				if err := s.run(ctx, "openssl", "req", "-new", "-key", keyPath, "-out", reqPath, "-subj", "/CN="+cn); err != nil {
					return nil, err
				}
			} else if err := s.easy(ctx, "gen-req", cn, "nopass"); err != nil {
				return nil, err
			}
		}
		args := []string{"sign-req", "client", cn}
		if expiresAt != 0 {
			end := time.Unix(expiresAt, 0).UTC()
			if !end.After(time.Now()) {
				return nil, problem(409, "Дата окончания выпускаемого сертификата уже прошла")
			}
			args = append([]string{"--enddate=" + end.Format("20060102150405Z")}, args...)
		}
		if err := s.easy(ctx, args...); err != nil {
			return nil, err
		}
	}
	cert, certPEM, err := readCert(certPath)
	if err != nil {
		return nil, err
	}
	ca, _, err := readCert(s.path("ca.crt"))
	if err != nil {
		return nil, err
	}
	if err := cert.CheckSignatureFrom(ca); err != nil {
		return nil, err
	}
	if expiresAt != 0 && cert.NotAfter.Unix() != expiresAt {
		return nil, fmt.Errorf("certificate expiry does not match the operation")
	}
	if cert.Subject.CommonName != cn || (expiresAt == 0 && !cert.NotAfter.After(time.Now())) {
		return nil, fmt.Errorf("certificate name/lifetime mismatch")
	}
	clientAuth := false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if !clientAuth {
		return nil, fmt.Errorf("certificate is not a client certificate")
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	if _, err := tls.X509KeyPair(certPEM, key); err != nil {
		return nil, fmt.Errorf("certificate and private key do not match")
	}
	return cert, nil
}

func (s *Service) index() (map[string]string, error) {
	b, err := os.ReadFile(s.path("index.txt"))
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 6 {
			return nil, fmt.Errorf("invalid PKI index record")
		}
		serial, ok := new(big.Int).SetString(fields[3], 16)
		if !ok {
			return nil, fmt.Errorf("invalid PKI serial")
		}
		result[Serial(serial)] = fields[0]
	}
	return result, nil
}

func atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".desk-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *Service) publishCRL(ctx context.Context, required []string) error {
	ca, _, err := readCert(s.path("ca.crt"))
	if err != nil {
		return err
	}
	if time.Now().Before(ca.NotBefore) || !time.Now().Before(ca.NotAfter) {
		return fmt.Errorf("CA is not currently valid; CRL renewal requires repair")
	}
	index, err := s.index()
	if err != nil {
		return err
	}
	for serial, state := range index {
		if state == "R" {
			required = append(required, serial)
		}
	}
	// Never lose a previously published revocation, even after an inconsistent
	// restore of the PKI index. Expired, correctly signed CRLs still count.
	if previous, err := readCRL(filepath.Join(s.RuntimeDir, "crl.pem"), ca); err == nil {
		for _, entry := range previous.RevokedCertificateEntries {
			required = append(required, Serial(entry.SerialNumber))
		}
	}
	if err := s.easy(ctx, "gen-crl"); err != nil {
		return err
	}
	crl, err := readCRL(s.path("crl.pem"), ca)
	if err != nil {
		return err
	}
	if !crl.NextUpdate.After(time.Now()) || crl.ThisUpdate.After(time.Now().Add(time.Minute)) {
		return fmt.Errorf("invalid CRL validity period")
	}
	revoked := map[string]bool{}
	for _, entry := range crl.RevokedCertificateEntries {
		revoked[Serial(entry.SerialNumber)] = true
	}
	for _, serial := range required {
		if !revoked[serial] {
			return fmt.Errorf("revoked serial missing in CRL")
		}
	}
	b, err := os.ReadFile(s.path("crl.pem"))
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.RuntimeDir, "crl.pem"), b)
}
