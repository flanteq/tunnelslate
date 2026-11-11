package vpnauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"tunnelslate/internal/management"
	"tunnelslate/internal/store"
	"tunnelslate/internal/vpnauthwire"
)

type Service struct {
	Store      *store.Store
	ControlDir string
	Management *management.Client
	Changed    func(...string)
	mu         sync.Mutex
	limitsMu   sync.Mutex
	limits     map[string]attempts
	slots      chan struct{}
}
type attempts struct {
	Count int
	Until time.Time
}
type Binding struct {
	Mode       string `json:"mode"`
	ProviderID string `json:"provider_id"`
	Username   string `json:"username"`
	Revision   int64  `json:"revision"`
}
type BindingView struct {
	Binding           Binding    `json:"binding"`
	Providers         []Provider `json:"providers"`
	DisconnectPending bool       `json:"disconnect_pending"`
}

func (s *Service) notify() {
	if s.Changed != nil {
		s.Changed("settings", "clients", "devices", "audit", "connections")
	}
}
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func (s *Service) Providers(ctx context.Context) ([]Provider, error) {
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT id,name,kind,enabled,configuration,encrypted_secret!='',revision FROM vpn_auth_providers ORDER BY name COLLATE NOCASE")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Provider{}
	for rows.Next() {
		var p Provider
		var data string
		if err = rows.Scan(&p.ID, &p.Name, &p.Kind, &p.Enabled, &data, &p.HasSecret, &p.Revision); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(data), &p.Config); err != nil {
			return nil, err
		}
		if p.Kind == "radius" && p.Config.TimeoutSeconds == 0 {
			p.Config.TimeoutSeconds = vpnauthwire.DefaultRADIUSTimeoutSeconds
		}
		result = append(result, p)
	}
	return result, rows.Err()
}
func (s *Service) provider(ctx context.Context, id string) (Provider, error) {
	var p Provider
	var data, secret string
	err := s.Store.DB.QueryRowContext(ctx, "SELECT id,name,kind,enabled,configuration,encrypted_secret,revision FROM vpn_auth_providers WHERE id=?", id).Scan(&p.ID, &p.Name, &p.Kind, &p.Enabled, &data, &secret, &p.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return p, problem(404, "vpn_auth.provider_not_found")
	}
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal([]byte(data), &p.Config); err != nil {
		return p, err
	}
	if p.Kind == "radius" && p.Config.TimeoutSeconds == 0 {
		p.Config.TimeoutSeconds = vpnauthwire.DefaultRADIUSTimeoutSeconds
	}
	p.Secret, err = s.Store.OpenVPNAuthSecret(p.ID, secret)
	return p, err
}
func (s *Service) SaveProvider(ctx context.Context, p Provider, actor string) (Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateProvider(&p); err != nil {
		return Provider{}, err
	}
	if p.ID == "" {
		if p.Revision != 0 {
			return Provider{}, problem(409, "vpn_auth.changed")
		}
		p.ID = newID()
	} else {
		old, err := s.provider(ctx, p.ID)
		if err != nil {
			return Provider{}, err
		}
		if old.Revision != p.Revision {
			return Provider{}, problem(409, "vpn_auth.changed")
		}
		if old.Kind != p.Kind {
			return Provider{}, problem(400, "vpn_auth.kind_immutable")
		}
		if p.Secret == "" {
			p.Secret = old.Secret
		}
	}
	if p.Secret == "" || (p.Kind == "radius" && utf8.RuneCountInString(p.Secret) < 16) {
		return Provider{}, problem(400, "vpn_auth.invalid_secret")
	}
	var duplicate bool
	if err := s.Store.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM vpn_auth_providers WHERE name=? COLLATE NOCASE AND id!=?)", p.Name, p.ID).Scan(&duplicate); err != nil {
		return Provider{}, err
	}
	if duplicate {
		return Provider{}, problem(409, "vpn_auth.duplicate_provider")
	}
	secret, err := s.Store.SealVPNAuthSecret(ctx, p.ID, p.Secret)
	if err != nil {
		return Provider{}, err
	}
	p.Revision++
	data, err := json.Marshal(p.Config)
	if err != nil {
		return Provider{}, err
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return Provider{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO vpn_auth_providers(id,name,kind,enabled,configuration,encrypted_secret,revision,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,configuration=excluded.configuration,encrypted_secret=excluded.encrypted_secret,revision=excluded.revision,updated_at=excluded.updated_at`, p.ID, p.Name, p.Kind, p.Enabled, string(data), secret, p.Revision, time.Now().Unix()); err != nil {
		return Provider{}, err
	}
	if err = queueDisconnects(ctx, tx, "provider", p.ID); err != nil {
		return Provider{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_events(actor,action,target,created_at) VALUES(?,'vpn.auth.provider.save',?,?)", actor, p.ID, time.Now().Unix()); err != nil {
		return Provider{}, err
	}
	if err = s.blockLocal(); err != nil {
		return Provider{}, err
	}
	if err = tx.Commit(); err != nil {
		return Provider{}, err
	}
	defer s.notify()
	if err = s.publishLocked(ctx); err != nil {
		return Provider{}, err
	}
	p.Secret = ""
	p.HasSecret = true
	return p, nil
}
func (s *Service) DeleteProvider(ctx context.Context, id string, revision int64, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.provider(ctx, id)
	if err != nil {
		return err
	}
	if p.Revision != revision {
		return problem(409, "vpn_auth.changed")
	}
	var used bool
	if err = s.Store.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM client_vpn_auth a JOIN clients c ON c.id=a.client_id WHERE a.provider_id=? AND c.deleted_at IS NULL)`, id).Scan(&used); err != nil {
		return err
	}
	if used {
		return problem(409, "vpn_auth.provider_in_use")
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, query := range []string{"DELETE FROM client_vpn_auth WHERE provider_id=?", "DELETE FROM vpn_auth_providers WHERE id=?"} {
		if _, err = tx.ExecContext(ctx, query, id); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_events(actor,action,target,created_at) VALUES(?,'vpn.auth.provider.delete',?,?)", actor, id, time.Now().Unix()); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.notify()
	return nil
}
func (s *Service) Binding(ctx context.Context, id string) (BindingView, error) {
	var v BindingView
	v.Binding.Mode = "certificate"
	var exists bool
	if err := s.Store.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM clients WHERE id=? AND deleted_at IS NULL)", id).Scan(&exists); err != nil {
		return v, err
	}
	if !exists {
		return v, problem(404, "vpn_auth.subject_not_found")
	}
	err := s.Store.DB.QueryRowContext(ctx, "SELECT COALESCE(provider_id,''),username,revision FROM client_vpn_auth WHERE client_id=?", id).Scan(&v.Binding.ProviderID, &v.Binding.Username, &v.Binding.Revision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return v, err
	}
	if v.Binding.ProviderID != "" {
		v.Binding.Mode = "external"
	}
	v.Providers, err = s.Providers(ctx)
	if err != nil {
		return v, err
	}
	err = s.Store.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_auth_disconnects q JOIN certificates x ON x.common_name=q.common_name JOIN devices d ON d.id=x.device_id WHERE d.client_id=?)`, id).Scan(&v.DisconnectPending)
	return v, err
}
func (s *Service) SaveBinding(ctx context.Context, id string, b Binding, actor string) (BindingView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.Binding(ctx, id)
	if err != nil {
		return BindingView{}, err
	}
	if old.Binding.Revision != b.Revision {
		return BindingView{}, problem(409, "vpn_auth.changed")
	}
	if b.Mode == "external" {
		if !usernamePattern.MatchString(b.Username) {
			return BindingView{}, problem(400, "vpn_auth.invalid_username")
		}
		p, err := s.provider(ctx, b.ProviderID)
		if err != nil {
			return BindingView{}, err
		}
		if !p.Enabled {
			return BindingView{}, problem(400, "vpn_auth.provider_disabled")
		}
	} else if b.Mode == "certificate" {
		b.ProviderID = ""
		b.Username = ""
	} else {
		return BindingView{}, problem(400, "vpn_auth.invalid_binding")
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return BindingView{}, err
	}
	defer tx.Rollback()
	var provider any
	if b.ProviderID != "" {
		provider = b.ProviderID
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO client_vpn_auth(client_id,provider_id,username,revision) VALUES(?,?,?,?) ON CONFLICT(client_id) DO UPDATE SET provider_id=excluded.provider_id,username=excluded.username,revision=excluded.revision`, id, provider, b.Username, b.Revision+1)
	if err != nil {
		return BindingView{}, err
	}
	if err = queueDisconnects(ctx, tx, "client", id); err != nil {
		return BindingView{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_events(actor,action,target,created_at) VALUES(?,'vpn.auth.binding.save',?,?)", actor, id, time.Now().Unix()); err != nil {
		return BindingView{}, err
	}
	if err = s.blockLocal(); err != nil {
		return BindingView{}, err
	}
	if err = tx.Commit(); err != nil {
		return BindingView{}, err
	}
	defer s.notify()
	if err = s.publishLocked(ctx); err != nil {
		return BindingView{}, err
	}
	return s.Binding(ctx, id)
}

// Invalidate the local allow-list BEFORE committing policy changes. A crash in
// between leaves new logins denied instead of using a stale weaker policy.
func (s *Service) blockLocal() error {
	return s.writePolicy(vpnauthwire.Policy{Entries: map[string]vpnauthwire.Entry{}})
}

const effectiveProvider = `b.provider_id`
const effectiveRevision = `b.revision`
const effectiveUsername = `b.username`

func queueDisconnects(ctx context.Context, tx *sql.Tx, kind, id string) error {
	where := "d.client_id=?"
	if kind == "provider" {
		where = "(" + effectiveProvider + ")=?"
	}
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO vpn_auth_disconnects(common_name) SELECT x.common_name FROM certificates x JOIN devices d ON d.id=x.device_id LEFT JOIN client_vpn_auth b ON b.client_id=d.client_id WHERE `+where, id)
	return err
}
func (s *Service) Publish(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.publishLocked(ctx)
}
func (s *Service) publishLocked(ctx context.Context) error {
	rows, err := s.Store.DB.QueryContext(ctx, `SELECT x.common_name,x.serial,x.not_after,d.id,COALESCE(`+effectiveProvider+`,''),COALESCE(`+effectiveUsername+`,''),COALESCE(p.revision,0),COALESCE(`+effectiveRevision+`,0) FROM certificates x JOIN devices d ON d.id=x.device_id JOIN clients c ON c.id=d.client_id JOIN operations o ON o.id=x.operation_id LEFT JOIN client_vpn_auth b ON b.client_id=c.id LEFT JOIN vpn_auth_providers p ON p.id=(`+effectiveProvider+`) WHERE x.status='valid' AND x.not_after>? AND o.state='succeeded' AND d.deleted_at IS NULL AND c.deleted_at IS NULL AND c.disabled=0 AND NOT EXISTS(SELECT 1 FROM vpn_auth_disconnects q WHERE q.common_name=x.common_name) AND NOT EXISTS(SELECT 1 FROM operations z WHERE z.state IN ('pending','running','partial') AND (z.device_id=d.id OR (z.client_id=c.id AND z.kind IN ('delete_client','revoke_client'))))`, time.Now().Unix())
	if err != nil {
		return err
	}
	p := vpnauthwire.Policy{Entries: map[string]vpnauthwire.Entry{}}
	for rows.Next() {
		var cn string
		var e vpnauthwire.Entry
		var identity authIdentity
		if err = rows.Scan(&cn, &e.Serial, &e.NotAfter, &identity.DeviceID, &identity.ProviderID, &identity.Username, &identity.ProviderRevision, &identity.BindingRevision); err != nil {
			rows.Close()
			return err
		}
		e.External = identity.ProviderID != ""
		identity.Serial = e.Serial
		e.Version = identity.version()
		p.Entries[cn] = e
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	return s.writePolicy(p)
}
func (s *Service) writePolicy(p vpnauthwire.Policy) error {
	if s.ControlDir == "" {
		return nil
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(s.ControlDir, 0700); err != nil {
		return err
	}
	path := filepath.Join(s.ControlDir, vpnauthwire.PolicyName)
	old, _ := os.ReadFile(path)
	if bytes.Equal(old, b) {
		return nil
	}
	f, err := os.CreateTemp(s.ControlDir, ".vpn-auth-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(s.ControlDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *Service) ProcessDisconnects(ctx context.Context) error {
	if s.Management == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.Store.DB.QueryContext(ctx, "SELECT common_name FROM vpn_auth_disconnects LIMIT 32")
	if err != nil {
		return err
	}
	names := []string{}
	for rows.Next() {
		var cn string
		if err = rows.Scan(&cn); err != nil {
			rows.Close()
			return err
		}
		names = append(names, cn)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, cn := range names {
		if err = s.Management.Disconnect(ctx, cn); err != nil {
			return err
		}
		if _, err = s.Store.DB.ExecContext(ctx, "DELETE FROM vpn_auth_disconnects WHERE common_name=?", cn); err != nil {
			return err
		}
	}
	if len(names) > 0 {
		s.notify()
		return s.publishLocked(ctx)
	}
	return nil
}

// Used by profile generation, without importing a provider or any secrets.
func RequiresPassword(ctx context.Context, db *sql.DB, deviceID string) (bool, error) {
	var external bool
	err := db.QueryRowContext(ctx, `SELECT COALESCE(`+effectiveProvider+`,'')!='' FROM devices d LEFT JOIN client_vpn_auth b ON b.client_id=d.client_id WHERE d.id=?`, deviceID).Scan(&external)
	return external, err
}
