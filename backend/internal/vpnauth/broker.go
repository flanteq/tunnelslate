package vpnauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tunnelslate/internal/management"
	"tunnelslate/internal/vpnauthwire"
)

func (s *Service) Start(ctx context.Context) error {
	if err := s.Publish(ctx); err != nil {
		return err
	}
	path := filepath.Join(s.ControlDir, vpnauthwire.SocketName)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("VPN authentication socket path is not a socket")
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		return err
	}
	s.mu.Lock()
	s.slots = make(chan struct{}, 16)
	s.mu.Unlock()
	go func() { <-ctx.Done(); listener.Close() }()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case s.slots <- struct{}{}:
				go func() { defer func() { <-s.slots }(); defer conn.Close(); s.handle(ctx, conn) }()
			default:
				conn.Close()
			}
		}
	}()
	return nil
}
func (s *Service) handle(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var request vpnauthwire.Request
	decoder := json.NewDecoder(io.LimitReader(conn, vpnauthwire.MaxRequest+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(vpnauthwire.AuthSocketTimeout))
	work, cancel := context.WithTimeout(ctx, vpnauthwire.AuthWorkTimeout)
	defer cancel()
	_ = json.NewEncoder(conn).Encode(s.authenticate(work, request))
}

type authIdentity struct {
	DeviceID, ProviderID, Username, Serial string
	NotAfter                               int64
	ProviderRevision                       int64
	BindingRevision                        int64
}

func (s *Service) identity(ctx context.Context, r vpnauthwire.Request) (authIdentity, error) {
	var i authIdentity
	if !management.ValidCN(r.CommonName) || vpnauthwire.Serial(r.Serial) == "" {
		return i, sql.ErrNoRows
	}
	err := s.Store.DB.QueryRowContext(ctx, `SELECT d.id,COALESCE(`+effectiveProvider+`,''),COALESCE(`+effectiveUsername+`,''),x.serial,x.not_after,COALESCE(p.revision,0),COALESCE(`+effectiveRevision+`,0) FROM certificates x JOIN devices d ON d.id=x.device_id JOIN clients c ON c.id=d.client_id JOIN operations o ON o.id=x.operation_id LEFT JOIN client_vpn_auth b ON b.client_id=c.id LEFT JOIN vpn_auth_providers p ON p.id=(`+effectiveProvider+`) WHERE x.common_name=? AND x.status='valid' AND x.not_after>? AND o.state='succeeded' AND d.deleted_at IS NULL AND c.deleted_at IS NULL AND c.disabled=0 AND NOT EXISTS(SELECT 1 FROM vpn_auth_disconnects q WHERE q.common_name=x.common_name) AND NOT EXISTS(SELECT 1 FROM operations z WHERE z.state IN ('pending','running','partial') AND (z.device_id=d.id OR (z.client_id=c.id AND z.kind IN ('delete_client','revoke_client'))))`, r.CommonName, time.Now().Unix()).Scan(&i.DeviceID, &i.ProviderID, &i.Username, &i.Serial, &i.NotAfter, &i.ProviderRevision, &i.BindingRevision)
	if err == nil && vpnauthwire.Serial(i.Serial) != vpnauthwire.Serial(r.Serial) {
		err = sql.ErrNoRows
	}
	return i, err
}
func (s *Service) Authenticate(ctx context.Context, r vpnauthwire.Request) bool {
	return s.authenticate(ctx, r).Allowed
}
func (i authIdentity) version() string {
	return vpnauthwire.Version(i.DeviceID, i.Serial, i.ProviderID, i.Username, i.ProviderRevision, i.BindingRevision)
}
func (s *Service) authenticate(ctx context.Context, r vpnauthwire.Request) vpnauthwire.Response {
	ip := net.ParseIP(r.IP)
	if ip == nil {
		return vpnauthwire.Response{}
	}
	r.IP = ip.String()
	if len(r.Password) > 4096 || strings.ContainsAny(r.Password, "\r\n\x00") {
		return vpnauthwire.Response{}
	}
	s.mu.Lock()
	identity, err := s.identity(ctx, r)
	s.mu.Unlock()
	if err != nil {
		return vpnauthwire.Response{}
	}
	if identity.ProviderID == "" {
		return vpnauthwire.Response{Allowed: true, Version: identity.version()}
	}
	if !s.allowExternal(r.IP, identity.DeviceID) {
		return vpnauthwire.Response{}
	}
	accepted := false
	if r.Username == identity.Username && usernamePattern.MatchString(r.Username) && r.Password != "" {
		s.mu.Lock()
		p, loadErr := s.provider(ctx, identity.ProviderID)
		s.mu.Unlock()
		if loadErr == nil && p.Enabled && p.Revision == identity.ProviderRevision {
			accepted, err = authenticateProvider(ctx, p, r.Username, r.Password, r.IP)
			if err != nil {
				slog.Warn("VPN external authentication unavailable", "provider_id", p.ID)
			}
		}
	}
	// Revocation, reassignment or provider updates while a remote request is in
	// flight must not grant access using the previous policy.
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.identity(ctx, r)
	if err != nil || current != identity {
		accepted = false
	}
	action, severity := "vpn.auth.accept", "INFO"
	if !accepted {
		action, severity = "vpn.auth.reject", "WARNING"
		s.recordFailure(r.IP, identity.DeviceID)
	}
	_, err = s.Store.DB.ExecContext(ctx, "INSERT INTO audit_events(actor,action,target,severity,created_at) VALUES(?,?,?,?,?)", "vpn:"+r.IP, action, identity.DeviceID, severity, time.Now().Unix())
	if err != nil {
		return vpnauthwire.Response{}
	}
	if s.Changed != nil {
		s.Changed("audit", "dashboard")
	}
	if !accepted {
		return vpnauthwire.Response{}
	}
	return vpnauthwire.Response{Allowed: true, Version: identity.version()}
}
func authenticateProvider(ctx context.Context, p Provider, username, password, ip string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, providerTimeout(p))
	defer cancel()
	if username == "" || password == "" {
		return false, nil
	}
	switch p.Kind {
	case "ldap":
		return authenticateLDAP(ctx, p, username, password)
	case "radius":
		return authenticateRADIUS(ctx, p, username, password, ip)
	}
	return false, errors.New("unsupported authentication provider")
}
func (s *Service) allowExternal(ip, device string) bool {
	s.limitsMu.Lock()
	defer s.limitsMu.Unlock()
	now := time.Now()
	if s.limits == nil {
		s.limits = map[string]attempts{}
	}
	for key, b := range s.limits {
		if !now.Before(b.Until) {
			delete(s.limits, key)
		}
	}
	if len(s.limits) > 4090 {
		return false
	}
	for _, key := range []string{"ip:" + ip, "device:" + device} {
		if s.limits[key].Count >= 5 {
			return false
		}
	}
	key := "request:" + ip
	b := s.limits[key]
	if b.Until.IsZero() {
		b.Until = now.Add(time.Minute)
	}
	if b.Count >= 30 {
		return false
	}
	b.Count++
	s.limits[key] = b
	return true
}
func (s *Service) recordFailure(ip, device string) {
	s.limitsMu.Lock()
	defer s.limitsMu.Unlock()
	for _, key := range []string{"ip:" + ip, "device:" + device} {
		b := s.limits[key]
		if b.Until.IsZero() {
			b.Until = time.Now().Add(15 * time.Minute)
		}
		b.Count++
		s.limits[key] = b
	}
}
func (s *Service) Test(ctx context.Context, id, username, password string) error {
	if !usernamePattern.MatchString(username) || password == "" || len(password) > 4096 {
		return problem(400, "vpn_auth.invalid_username")
	}
	s.mu.Lock()
	p, err := s.provider(ctx, id)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, providerTimeout(p))
	defer cancel()
	ok, err := authenticateProvider(ctx, p, username, password, "127.0.0.1")
	if err != nil || !ok {
		return problem(400, "vpn_auth.test_failed")
	}
	return nil
}
