package pki

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type BootstrapStatus struct {
	State     string `json:"state"`
	Step      string `json:"step"`
	Error     string `json:"error"`
	UpdatedAt int64  `json:"updated_at"`
}

func (s *Service) runtimeReady() bool {
	if !s.Available() {
		return false
	}
	for _, name := range []string{".desk-ready", "server.conf", "ca.crt", "server.crt", "server.key", "crl.pem", "tls-crypt.key"} {
		info, err := os.Stat(filepath.Join(s.RuntimeDir, name))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return false
		}
	}
	return true
}

// A new CA is allowed only when no previous PKI/runtime material is present.
// A user-supplied base server.conf may be installed before first initialization.
func (s *Service) emptyInstallation() (bool, error) {
	for _, dir := range []string{s.PKIDir, s.RuntimeDir} {
		if dir == "" {
			return false, fmt.Errorf("PKI directories are not configured")
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return false, err
		}
		for _, entry := range entries {
			if (dir == s.PKIDir && entry.Name() == ".desk.lock") || (dir == s.RuntimeDir && (entry.Name() == "server.conf" || entry.Name() == "settings.env" || entry.Name() == "network.json")) {
				continue
			}
			return false, nil
		}
	}
	return true, nil
}

func (s *Service) InitializationStatus(ctx context.Context) (BootstrapStatus, error) {
	var status BootstrapStatus
	err := s.Store.DB.QueryRowContext(ctx, "SELECT state,step,error,updated_at FROM pki_bootstrap WHERE id=1").Scan(&status.State, &status.Step, &status.Error, &status.UpdatedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return status, err
	}
	if status.State == "running" {
		return status, nil
	}
	if s.runtimeReady() {
		status.State = "ready"
		return status, nil
	}
	if empty, err := s.emptyInstallation(); err == nil && empty && status.State == "" {
		status.State = "empty"
	} else if status.State == "" || status.State == "ready" {
		status.State = "incomplete"
		status.Error = "PKI or server files are incomplete. Restore or repair existing data; automatic reset is disabled."
	}
	return status, nil
}

func (s *Service) bootstrapStep(ctx context.Context, actor, step string) error {
	_, err := s.Store.DB.ExecContext(ctx, `INSERT INTO pki_bootstrap(id,state,step,actor,updated_at) VALUES (1,'running',?,?,?)
	 ON CONFLICT(id) DO UPDATE SET state='running',step=excluded.step,actor=excluded.actor,error='',updated_at=excluded.updated_at`, step, actor, time.Now().Unix())
	if err == nil {
		s.notify("settings")
	}
	return err
}

// PrepareExisting adopts the original installation and repairs runtime publication
// using its original keys. It never creates a new CA on process startup.
func (s *Service) PrepareExisting(ctx context.Context) error {
	if s.PKIDir == "" || s.RuntimeDir == "" {
		return nil
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	empty, err := s.emptyInstallation()
	if err != nil {
		return err
	}
	if empty {
		result, err := s.Store.DB.ExecContext(ctx, "UPDATE pki_bootstrap SET state='failed',error='Initialization was interrupted before PKI creation. Retry initialization.',updated_at=? WHERE id=1 AND state='running'", time.Now().Unix())
		if err == nil {
			if changed, _ := result.RowsAffected(); changed > 0 {
				s.notify("settings")
			}
		}
		return err
	}
	return s.initializeLocked(ctx, "system", false)
}

func (s *Service) Initialize(ctx context.Context, actor string) error {
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if s.runtimeReady() {
		return problem(409, "PKI is already initialized; replacing the CA is disabled")
	}
	return s.initializeLocked(ctx, actor, true)
}

func (s *Service) initializeLocked(ctx context.Context, actor string, allowCreate bool) (result error) {
	defer s.notify("settings", "dashboard", "audit", "connections")
	if err := s.bootstrapStep(ctx, actor, "verify_existing"); err != nil {
		return err
	}
	defer func() {
		if result == nil {
			return
		}
		saveCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := s.Store.DB.ExecContext(saveCtx, "UPDATE pki_bootstrap SET state='failed',error=?,updated_at=? WHERE id=1", result.Error(), time.Now().Unix()); err != nil {
			result = fmt.Errorf("initialization failed and journal update failed: %w", err)
		}
	}()
	if err := os.Remove(filepath.Join(s.RuntimeDir, ".desk-ready")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	empty, err := s.emptyInstallation()
	if err != nil {
		return err
	}
	if empty {
		if !allowCreate {
			return fmt.Errorf("new PKI requires initialization from the admin panel")
		}
		for _, stage := range []struct {
			step string
			args []string
		}{
			{"create_pki", []string{"init-pki"}},
			{"create_ca", []string{"build-ca", "nopass"}},
			{"create_server", []string{"build-server-full", "server", "nopass"}},
		} {
			if err := s.bootstrapStep(ctx, actor, stage.step); err != nil {
				return err
			}
			var env []string
			if stage.step == "create_ca" {
				env = []string{"EASYRSA_REQ_CN=TunnelSlate-CA"}
			}
			if err := s.runEnv(ctx, env, "/usr/share/easy-rsa/easyrsa", stage.args...); err != nil {
				return err
			}
		}
		// OpenVPN static key V1: 2048 random bits, sixteen 32-character hex lines.
		var key [256]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		var text strings.Builder
		text.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
		for i := 0; i < len(key); i += 16 {
			text.WriteString(hex.EncodeToString(key[i : i+16]))
			text.WriteByte('\n')
		}
		text.WriteString("-----END OpenVPN Static key V1-----\n")
		if err := atomicWrite(s.path("private", "desk-tls-crypt.key"), []byte(text.String())); err != nil {
			return err
		}
	}
	if err := s.bootstrapStep(ctx, actor, "validate_pki"); err != nil {
		return err
	}
	for _, name := range []string{"ca.crt", "private/ca.key", "issued/server.crt", "private/server.key", "index.txt", "serial"} {
		info, err := os.Lstat(s.path(name))
		if err != nil || !info.Mode().IsRegular() {
			return problem(409, "Incomplete existing PKI: missing or invalid "+name+". Restore or repair it; automatic reset is disabled.")
		}
	}
	ca, caPEM, err := readCert(s.path("ca.crt"))
	if err != nil {
		return err
	}
	caKey, err := os.ReadFile(s.path("private", "ca.key"))
	if err != nil {
		return err
	}
	if _, err := tls.X509KeyPair(caPEM, caKey); err != nil {
		return fmt.Errorf("CA certificate and key do not match")
	}
	server, serverPEM, err := readCert(s.path("issued", "server.crt"))
	if err != nil {
		return err
	}
	serverKey, err := os.ReadFile(s.path("private", "server.key"))
	if err != nil {
		return err
	}
	if _, err := tls.X509KeyPair(serverPEM, serverKey); err != nil {
		return fmt.Errorf("server certificate and key do not match")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := server.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("server certificate verification failed: %w", err)
	}
	if server.Subject.CommonName != "server" {
		return fmt.Errorf("server certificate common name must be server")
	}
	index, err := s.index()
	if err != nil {
		return err
	}
	if index[Serial(server.SerialNumber)] != "V" {
		return fmt.Errorf("server certificate is not valid in the PKI index")
	}
	// Adopt the original scaffold key without changing any existing client profile.
	tlsPath := s.path("private", "desk-tls-crypt.key")
	tlsKey, err := os.ReadFile(tlsPath)
	if errors.Is(err, os.ErrNotExist) {
		tlsKey, err = os.ReadFile(filepath.Join(s.RuntimeDir, "tls-crypt.key"))
		if err != nil {
			return fmt.Errorf("existing PKI has no tls-crypt key; restore it rather than replacing credentials")
		}
		if err := atomicWrite(tlsPath, tlsKey); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := validateTLSKey(tlsKey); err != nil {
		return err
	}
	if err := s.bootstrapStep(ctx, actor, "publish_runtime"); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"ca.crt": caPEM, "server.crt": serverPEM, "server.key": serverKey, "tls-crypt.key": tlsKey} {
		if err := atomicWrite(filepath.Join(s.RuntimeDir, name), data); err != nil {
			return err
		}
	}
	var revoked []string
	for serial, state := range index {
		if state == "R" {
			revoked = append(revoked, serial)
		}
	}
	if err := s.publishCRL(ctx, revoked); err != nil {
		return err
	}
	conf := filepath.Join(s.RuntimeDir, "server.conf")
	if _, err := os.Stat(conf); errors.Is(err, os.ErrNotExist) {
		data, err := os.ReadFile("/usr/share/tunnelslate/server.conf")
		if err != nil {
			return err
		}
		if err := atomicWrite(conf, data); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if info, err := os.Stat(conf); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Errorf("existing server.conf is empty or unreadable; restore it")
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE pki_bootstrap SET state='ready',step='complete',error='',updated_at=? WHERE id=1", time.Now().Unix()); err != nil {
		return err
	}
	action := "pki.initialize"
	if !allowCreate {
		action = "pki.runtime.prepare"
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_events(actor,action,created_at) VALUES (?,?,?)", actor, action, time.Now().Unix()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	fingerprint := sha256.Sum256(ca.Raw)
	return atomicWrite(filepath.Join(s.RuntimeDir, ".desk-ready"), []byte(hex.EncodeToString(fingerprint[:])+"\n"))
}

func validateTLSKey(data []byte) error {
	var encoded strings.Builder
	inside, ended := false, false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "-----BEGIN OpenVPN Static key V1-----" {
			inside = true
			continue
		}
		if line == "-----END OpenVPN Static key V1-----" {
			ended = true
			break
		}
		if inside {
			encoded.WriteString(line)
		}
	}
	key, err := hex.DecodeString(encoded.String())
	if !inside || !ended || err != nil || len(key) != 256 {
		return fmt.Errorf("invalid tls-crypt key; restore the original key")
	}
	return nil
}
