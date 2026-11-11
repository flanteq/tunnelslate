package pki

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"tunnelslate/internal/management"
	"tunnelslate/internal/store"
	"tunnelslate/internal/vpnauth"
	"tunnelslate/internal/vpnauthwire"
	"tunnelslate/internal/vpnoptions"
)

type Service struct {
	Changed            func(...string)
	Store              *store.Store
	Management         *management.Client
	PKIDir, RuntimeDir string
	CCDDir             string
	PublishAuth        func(context.Context) error
}

func (s *Service) notify(names ...string) {
	if s.Changed != nil {
		s.Changed(names...)
	}
}

type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string               { return e.Message }
func problem(code int, message string) error { return &Error{code, message} }
func NewID() (string, error)                 { return id() }
func ValidName(name string) bool {
	return len(name) > 0 && len(name) <= 128 && !strings.ContainsFunc(name, unicode.IsControl)
}

type Reference struct {
	Serial string `json:"serial"`
	CN     string `json:"cn"`
}
type Arguments struct {
	ExpiresAt int64       `json:"expires_at,omitempty"`
	CN        string      `json:"cn"`
	Old       []Reference `json:"old"`
}
type Operation struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	State        string `json:"state"`
	Step         string `json:"step"`
	DeviceID     string `json:"device_id"`
	DeviceName   string `json:"device_name,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientName   string `json:"client_name,omitempty"`
	Actor        string `json:"actor"`
	ResultSerial string `json:"result_serial"`
	Error        string `json:"error"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

var requestKey = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,80}$`)

func (s *Service) operation(ctx context.Context, id string) (Operation, Arguments, error) {
	var op Operation
	var arguments string
	err := s.Store.DB.QueryRowContext(ctx, `SELECT o.id,o.kind,o.state,o.step,COALESCE(o.device_id,''),o.actor,o.result_serial,o.error,o.created_at,o.updated_at,o.arguments,COALESCE(o.client_id,d.client_id,'') FROM operations o LEFT JOIN devices d ON d.id=o.device_id WHERE o.id=?`, id).Scan(&op.ID, &op.Kind, &op.State, &op.Step, &op.DeviceID, &op.Actor, &op.ResultSerial, &op.Error, &op.CreatedAt, &op.UpdatedAt, &arguments, &op.ClientID)
	if errors.Is(err, sql.ErrNoRows) {
		return op, Arguments{}, problem(404, "Operation not found")
	}
	if err != nil {
		return op, Arguments{}, err
	}
	var args Arguments
	err = json.Unmarshal([]byte(arguments), &args)
	return op, args, err
}

// Start records intent BEFORE touching the filesystem. Repeated keys replay exactly one operation.
func (s *Service) Start(ctx context.Context, actor, key, kind, target, name string) (Operation, error) {
	return s.StartWithExpiry(ctx, actor, key, kind, target, name, "")
}

func (s *Service) StartWithExpiry(ctx context.Context, actor, key, kind, target, name, expiresOn string) (Operation, error) {
	if expiresOn != "" && kind != "issue" && kind != "rotate" {
		return Operation{}, problem(400, "Дата окончания доступна только при выпуске или перевыпуске")
	}

	if !requestKey.MatchString(key) {
		return Operation{}, problem(400, "A 16–80 character Idempotency-Key is required")
	}
	name = strings.TrimSpace(name)
	if kind == "issue" && !ValidName(name) {
		return Operation{}, problem(400, "Device name must be 1–128 bytes without control characters")
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return Operation{}, err
	}
	defer unlock()
	fingerprint := kind + "\x00" + target + "\x00" + name
	if expiresOn != "" {
		fingerprint += "\x00" + expiresOn
	}
	sum := sha256.Sum256([]byte(fingerprint))
	hash := hex.EncodeToString(sum[:])
	var existing, oldHash string
	err = s.Store.DB.QueryRowContext(ctx, "SELECT id,request_hash FROM operations WHERE request_key=?", key).Scan(&existing, &oldHash)
	if err == nil {
		if oldHash != hash {
			return Operation{}, problem(409, "Idempotency-Key was used for a different request")
		}
		return s.runLocked(ctx, existing)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Operation{}, err
	}
	opID, err := id()
	if err != nil {
		return Operation{}, err
	}
	args := Arguments{Old: []Reference{}}
	deviceID := target
	clientID := ""
	linkLocked := kind == "delete_client"
	if linkLocked {
		s.Store.LinkMu.Lock()
		defer func() {
			if linkLocked {
				s.Store.LinkMu.Unlock()
			}
		}()
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, err
	}
	defer tx.Rollback()
	switch kind {
	case "issue":
		clientID = target
		var disabled bool
		err = tx.QueryRowContext(ctx, "SELECT disabled FROM clients WHERE id=? AND deleted_at IS NULL", target).Scan(&disabled)
		if errors.Is(err, sql.ErrNoRows) {
			return Operation{}, problem(404, "Client not found")
		}
		if err != nil {
			return Operation{}, err
		}
		if disabled {
			return Operation{}, problem(409, "Client is disabled")
		}
		deviceID, err = id()
		if err != nil {
			return Operation{}, err
		}
		var duplicate int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM devices WHERE client_id=? AND name=? COLLATE NOCASE AND deleted_at IS NULL", target, name).Scan(&duplicate); err != nil {
			return Operation{}, err
		}
		if duplicate > 0 {
			return Operation{}, problem(409, "A device with this name already exists")
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES (?,?,?,?,?)", deviceID, target, name, "device-"+deviceID, time.Now().Unix()); err != nil {
			return Operation{}, err
		}
	case "rotate", "delete":
		var disabled bool
		err = tx.QueryRowContext(ctx, "SELECT c.disabled,c.id FROM devices d JOIN clients c ON c.id=d.client_id WHERE d.id=? AND d.deleted_at IS NULL AND c.deleted_at IS NULL", deviceID).Scan(&disabled, &clientID)
		if errors.Is(err, sql.ErrNoRows) {
			return Operation{}, problem(404, "Device not found")
		}
		if err != nil {
			return Operation{}, err
		}
		if disabled && kind == "rotate" {
			return Operation{}, problem(409, "Client is disabled")
		}
		rows, err := tx.QueryContext(ctx, "SELECT serial,common_name FROM certificates WHERE device_id=? AND (status!='revoked' OR ?='delete')", deviceID, kind)
		if err != nil {
			return Operation{}, err
		}
		for rows.Next() {
			var ref Reference
			if err := rows.Scan(&ref.Serial, &ref.CN); err != nil {
				rows.Close()
				return Operation{}, err
			}
			args.Old = append(args.Old, ref)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return Operation{}, err
		}
	case "revoke":
		var ref Reference
		err = tx.QueryRowContext(ctx, "SELECT c.device_id,c.serial,c.common_name,d.client_id FROM certificates c JOIN devices d ON d.id=c.device_id JOIN clients u ON u.id=d.client_id WHERE c.serial=? AND u.deleted_at IS NULL", target).Scan(&deviceID, &ref.Serial, &ref.CN, &clientID)
		if errors.Is(err, sql.ErrNoRows) {
			return Operation{}, problem(404, "Certificate not found")
		}
		if err != nil {
			return Operation{}, err
		}
		args.Old = append(args.Old, ref)
	case "delete_client":
		clientID, deviceID = target, ""
		var found string
		if err := tx.QueryRowContext(ctx, "SELECT id FROM clients WHERE id=? AND deleted_at IS NULL", clientID).Scan(&found); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return Operation{}, problem(404, "Client not found")
			}
			return Operation{}, err
		}
		rows, err := tx.QueryContext(ctx, "SELECT c.serial,c.common_name FROM certificates c JOIN devices d ON d.id=c.device_id WHERE d.client_id=? ORDER BY c.rowid", clientID)
		if err != nil {
			return Operation{}, err
		}
		for rows.Next() {
			var ref Reference
			if err := rows.Scan(&ref.Serial, &ref.CN); err != nil {
				rows.Close()
				return Operation{}, err
			}
			args.Old = append(args.Old, ref)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return Operation{}, err
		}
	default:
		return Operation{}, problem(400, "Unknown PKI operation")
	}
	var active int
	if kind == "delete_client" {
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM operations o LEFT JOIN devices d ON d.id=o.device_id WHERE COALESCE(o.client_id,d.client_id)=? AND o.state IN ('pending','running','partial')`, clientID).Scan(&active); err != nil {
			return Operation{}, err
		}
		if active > 0 {
			return Operation{}, problem(409, "Client has unfinished operations; complete them before deleting the client")
		}
	} else {
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE client_id=? AND kind IN ('delete_client','revoke_client') AND state IN ('pending','running','partial')", clientID).Scan(&active); err != nil {
			return Operation{}, err
		}
		if active > 0 {
			return Operation{}, problem(409, "Client access operation is unfinished; complete that operation first")
		}
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE device_id=? AND state IN ('pending','running','partial')", deviceID).Scan(&active); err != nil {
		return Operation{}, err
	}
	if active > 0 {
		return Operation{}, problem(409, "Device already has an unfinished operation; retry that operation")
	}
	if (kind != "delete_client" || len(args.Old) > 0) && !s.Available() {
		return Operation{}, problem(503, "PKI is not initialized")
	}
	if kind == "issue" || kind == "rotate" {
		ca, _, err := readCert(s.path("ca.crt"))
		if err != nil {
			return Operation{}, err
		}
		end, err := certificateExpiration(expiresOn, time.Now(), ca.NotAfter)
		if err != nil {
			return Operation{}, err
		}
		args.ExpiresAt = end.Unix()
		cn, err := id()
		if err != nil {
			return Operation{}, err
		}
		args.CN = "desk-" + cn
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		return Operation{}, err
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,kind,state,step,device_id,client_id,actor,request_key,request_hash,arguments,created_at,updated_at) VALUES (?,?,'pending','queued',NULLIF(?,''),?,?,?,?,?,?,?)`, opID, kind, deviceID, clientID, actor, key, hash, string(encoded), now, now); err != nil {
		return Operation{}, err
	}
	if kind == "delete_client" {
		if _, err := tx.ExecContext(ctx, "DELETE FROM client_links WHERE client_id=?", clientID); err != nil {
			return Operation{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Operation{}, err
	}
	if linkLocked {
		s.Store.LinkMu.Unlock()
		linkLocked = false
	}
	s.notify("clients", "devices", "operations")
	return s.runLocked(ctx, opID)
}

func (s *Service) Run(ctx context.Context, id string) (Operation, error) {
	unlock, err := s.lock(ctx)
	if err != nil {
		return Operation{}, err
	}
	defer unlock()
	return s.runLocked(ctx, id)
}
func (s *Service) step(ctx context.Context, id, step string) error {
	_, err := s.Store.DB.ExecContext(ctx, "UPDATE operations SET state='running',step=?,error='',updated_at=? WHERE id=?", step, time.Now().Unix(), id)
	if err == nil {
		s.notify("operations", "devices")
	}
	return err
}
func (s *Service) runLocked(ctx context.Context, id string) (Operation, error) {
	op, args, err := s.operation(ctx, id)
	if err != nil {
		return op, err
	}
	if op.State == "succeeded" {
		return op, nil
	}
	if op.State == "failed" {
		return op, problem(409, "Операция отменена; создайте новую операцию")
	}
	if op.Kind != "revoke_client" {
		var blocked bool
		if err := s.Store.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM operations WHERE client_id=? AND kind='revoke_client' AND state IN ('pending','running','partial'))`, op.ClientID).Scan(&blocked); err != nil {
			return op, err
		}
		if blocked {
			return op, problem(409, "Emergency client revocation is pending")
		}
	}
	defer s.notify("dashboard", "clients", "devices", "certificates", "operations", "audit", "connections", "settings")
	if args.CN != "" && args.ExpiresAt != 0 && args.ExpiresAt <= time.Now().Unix() {
		if _, statErr := os.Stat(s.path("issued", args.CN+".crt")); errors.Is(statErr, os.ErrNotExist) {
			message := "Срок выпускаемого сертификата уже истёк; выпуск отменён"
			if _, err := s.Store.DB.ExecContext(ctx, "UPDATE operations SET state='failed',step='certificate_expired',error=?,updated_at=? WHERE id=?", message, time.Now().Unix(), op.ID); err != nil {
				return op, err
			}
			op, _, err := s.operation(ctx, op.ID)
			if err != nil {
				return op, err
			}
			return op, problem(409, message)
		} else if statErr != nil {
			return op, statErr
		}
	}
	err = s.execute(ctx, &op, args)
	if err != nil {
		// Persist even when the HTTP client disconnected or the process is shutting down.
		saveCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, saveErr := s.Store.DB.ExecContext(saveCtx, "UPDATE operations SET state='partial',error=?,updated_at=? WHERE id=?", err.Error(), time.Now().Unix(), op.ID); saveErr != nil {
			return op, fmt.Errorf("operation failed and journal update failed: %w", saveErr)
		}
		op, _, loadErr := s.operation(saveCtx, id)
		if loadErr != nil {
			return op, loadErr
		}
		return op, err
	}
	op, _, err = s.operation(ctx, id)
	return op, err
}

func (s *Service) execute(ctx context.Context, op *Operation, args Arguments) error {
	if op.Kind == "revoke_client" {
		var err error
		args, err = s.prepareClientRevocation(ctx, *op)
		if err != nil {
			return err
		}
	}
	needsPKI := (op.Kind != "delete_client" && op.Kind != "revoke_client") || len(args.Old) > 0
	if needsPKI && !s.Available() {
		return fmt.Errorf("PKI is unavailable")
	}
	if args.CN != "" {
		if err := s.step(ctx, op.ID, "issue_certificate"); err != nil {
			return err
		}
		cert, err := s.issue(ctx, args.CN, args.ExpiresAt)
		if err != nil {
			return err
		}
		index, err := s.index()
		if err != nil {
			return err
		}
		if index[Serial(cert.SerialNumber)] != "V" {
			return fmt.Errorf("new certificate is not valid in the PKI index")
		}
		serial := Serial(cert.SerialNumber)
		if _, err := s.Store.DB.ExecContext(ctx, `INSERT INTO certificates(serial,device_id,status,not_before,not_after,common_name,operation_id) VALUES (?,?,'valid',?,?,?,?) ON CONFLICT(serial) DO NOTHING`, serial, op.DeviceID, cert.NotBefore.Unix(), cert.NotAfter.Unix(), args.CN, op.ID); err != nil {
			return err
		}
		if _, err := s.Store.DB.ExecContext(ctx, "UPDATE operations SET result_serial=? WHERE id=?", serial, op.ID); err != nil {
			return err
		}
	}
	revoked := []string{}
	for _, ref := range args.Old {
		if !management.ValidCN(ref.CN) {
			return fmt.Errorf("unmanaged certificate cannot be revoked")
		}
		if err := s.step(ctx, op.ID, "revoke_certificate"); err != nil {
			return err
		}
		index, err := s.index()
		if err != nil {
			return err
		}
		flag, ok := index[ref.Serial]
		if !ok {
			return fmt.Errorf("old serial is missing from the PKI index")
		}
		if flag != "R" {
			if err := s.easy(ctx, "revoke", ref.CN); err != nil {
				return err
			}
		}
		index, err = s.index()
		if err != nil {
			return err
		}
		if index[ref.Serial] != "R" {
			return fmt.Errorf("certificate revocation was not confirmed")
		}
		if _, err := s.Store.DB.ExecContext(ctx, "UPDATE certificates SET status='revoked',revoked_at=COALESCE(revoked_at,?) WHERE serial=?", time.Now().Unix(), ref.Serial); err != nil {
			return err
		}
		revoked = append(revoked, ref.Serial)
	}
	if needsPKI {
		if err := s.step(ctx, op.ID, "publish_crl"); err != nil {
			return err
		}
		if err := s.publishCRL(ctx, revoked); err != nil {
			return err
		}
	}
	if len(args.Old) > 0 {
		if err := s.step(ctx, op.ID, "disconnect_sessions"); err != nil {
			return err
		}
		for _, ref := range args.Old {
			if err := s.Management.Disconnect(ctx, ref.CN); err != nil {
				return fmt.Errorf("CRL published; session disconnect pending: %w", err)
			}
		}
	}
	if op.Kind == "delete" {
		if err := s.step(ctx, op.ID, "delete_profile"); err != nil {
			return err
		}
	}
	if op.Kind == "delete_client" {
		if err := s.step(ctx, op.ID, "delete_client"); err != nil {
			return err
		}
	}
	if s.CCDDir != "" {
		if err := s.step(ctx, op.ID, "publish_ccd"); err != nil {
			return err
		}
		if err := s.publishCCDLocked(ctx); err != nil {
			return err
		}
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if op.Kind == "delete_client" {
		now := time.Now().Unix()
		if _, err := tx.ExecContext(ctx, "UPDATE devices SET deleted_at=COALESCE(deleted_at,?) WHERE client_id=?", now, op.ClientID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE clients SET deleted_at=COALESCE(deleted_at,?) WHERE id=?", now, op.ClientID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE device_ccd SET static_ip='' WHERE device_id IN (SELECT id FROM devices WHERE client_id=?)", op.ClientID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM device_ccd_retired_ips WHERE device_id IN (SELECT id FROM devices WHERE client_id=?)", op.ClientID); err != nil {
			return err
		}
	}
	if op.Kind == "delete" {
		// Hide the profile only after CRL publication and confirmed disconnection.
		// Keep PKI/index, certificate rows and journal references for recovery/audit.
		if _, err := tx.ExecContext(ctx, "UPDATE devices SET deleted_at=COALESCE(deleted_at,?) WHERE id=?", time.Now().Unix(), op.DeviceID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE device_ccd SET static_ip='' WHERE device_id=?", op.DeviceID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM device_ccd_retired_ips WHERE device_id=?", op.DeviceID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE operations SET state='succeeded',step='complete',error='',updated_at=? WHERE id=?", time.Now().Unix(), op.ID); err != nil {
		return err
	}
	target := op.DeviceID
	if op.Kind == "delete_client" || op.Kind == "revoke_client" {
		target = op.ClientID
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_events(actor,action,target,created_at) VALUES (?,?,?,?)", op.Actor, "pki."+op.Kind, target, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) Recover(ctx context.Context) error {
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT id FROM operations WHERE state IN ('pending','running','partial') ORDER BY CASE WHEN kind='revoke_client' THEN 0 ELSE 1 END,created_at LIMIT 100")
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var first error
	for _, id := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if op, err := s.Run(ctx, id); err != nil && first == nil && op.State != "failed" {
			first = err
		}
	}
	return first
}

type ProfileFile struct {
	Content  []byte
	Filename string
	Serial   string
}

func (s *Service) Profile(ctx context.Context, deviceID, endpoint string, port int, protocol, actor string, link vpnoptions.Link) (ProfileFile, error) {
	if err := link.Validate(); err != nil {
		return ProfileFile{}, err
	}
	if endpoint == "" {
		return ProfileFile{}, problem(409, "Set the public VPN hostname or IP in VPN settings")
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return ProfileFile{}, err
	}
	defer unlock()
	var serial, cn, clientName, deviceName string
	err = s.Store.DB.QueryRowContext(ctx, `SELECT c.serial,c.common_name,u.name,d.name FROM certificates c JOIN devices d ON d.id=c.device_id JOIN clients u ON u.id=d.client_id JOIN operations o ON o.id=c.operation_id WHERE c.device_id=? AND d.deleted_at IS NULL AND c.status='valid' AND c.not_after>? AND u.disabled=0 AND u.deleted_at IS NULL AND o.state='succeeded' AND NOT EXISTS(SELECT 1 FROM operations p WHERE (p.device_id=c.device_id OR (p.client_id=d.client_id AND p.kind IN ('delete_client','revoke_client'))) AND p.state IN ('pending','running','partial')) ORDER BY c.not_before DESC LIMIT 1`, deviceID, time.Now().Unix()).Scan(&serial, &cn, &clientName, &deviceName)
	if errors.Is(err, sql.ErrNoRows) {
		return ProfileFile{}, problem(409, "Device has no available profile; check certificate and operation status")
	}
	if err != nil {
		return ProfileFile{}, err
	}
	if !management.ValidCN(cn) {
		return ProfileFile{}, fmt.Errorf("invalid certificate reference")
	}
	index, err := s.index()
	if err != nil {
		return ProfileFile{}, err
	}
	if index[serial] != "V" {
		return ProfileFile{}, problem(409, "Certificate is not valid in the PKI")
	}
	cert, _, err := readCert(s.path("issued", cn+".crt"))
	if err != nil {
		return ProfileFile{}, err
	}
	ca, _, err := readCert(s.path("ca.crt"))
	if err != nil {
		return ProfileFile{}, err
	}
	key, err := os.ReadFile(s.path("private", cn+".key"))
	if err != nil {
		return ProfileFile{}, err
	}
	tlsKey, err := os.ReadFile(filepath.Join(s.RuntimeDir, "tls-crypt.key"))
	if err != nil {
		return ProfileFile{}, err
	}
	linkDirectives := link.Directives(protocol)
	externalAuth, err := vpnauth.RequiresPassword(ctx, s.Store.DB, deviceID)
	if err != nil {
		return ProfileFile{}, err
	}
	if externalAuth {
		linkDirectives += fmt.Sprintf("auth-user-pass\nhand-window %d\n", vpnauthwire.HandshakeWindowSeconds)
	}
	if protocol == "tcp" {
		protocol = "tcp-client"
	}
	profile := fmt.Sprintf("client\ndev tun\n%snobind\npersist-key\npersist-tun\nproto %s\nremote %s %d\nremote-cert-tls server\nverify-x509-name server name\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\nverb 3\n<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s\n</key>\n<tls-crypt>\n%s\n</tls-crypt>\n", linkDirectives, protocol, endpoint, port, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), key, tlsKey)
	if err := s.publishCCDLocked(ctx); err != nil {
		return ProfileFile{}, err
	}
	if err := s.Store.Audit(ctx, actor, "profile.download", deviceID); err != nil {
		return ProfileFile{}, err
	}
	return ProfileFile{Content: []byte(profile), Filename: profileFilename(clientName, deviceName, cert.NotAfter), Serial: serial}, nil
}
