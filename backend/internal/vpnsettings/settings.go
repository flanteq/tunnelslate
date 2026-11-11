package vpnsettings

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"tunnelslate/internal/config"
	"tunnelslate/internal/pki"
	"tunnelslate/internal/store"
	"tunnelslate/internal/vpnoptions"
)

type Settings struct {
	IsolateClients    bool     `json:"isolate_clients"`
	SiteToSite        bool     `json:"site_to_site"`
	SiteNAT           bool     `json:"site_nat"`
	Endpoint          string   `json:"endpoint"`
	Port              int      `json:"port"`
	ExternalPort      int      `json:"external_port"`
	Protocol          string   `json:"protocol"`
	Network           string   `json:"network"`
	DNS               []string `json:"dns"`
	DNSDomain         string   `json:"dns_domain"`
	DNSSearch         []string `json:"dns_search"`
	TunMTU            int      `json:"tun_mtu"`
	MSSMode           string   `json:"mss_mode"`
	MSS               int      `json:"mss"`
	RedirectGateway   bool     `json:"redirect_gateway"`
	Routes            []string `json:"routes"`
	DCO               string   `json:"dco"`
	MaxClients        int      `json:"max_clients"`
	KeepaliveInterval int      `json:"keepalive_interval"`
	KeepaliveTimeout  int      `json:"keepalive_timeout"`
	Revision          int64    `json:"revision"`
}

type Service struct {
	Store                  *store.Store
	RuntimeDir, ControlDir string
	mu                     sync.Mutex
	ValidateClients        func(context.Context, string) error
	PrepareClients         func(context.Context) error
}

func (s Settings) Link() vpnoptions.Link {
	return vpnoptions.Link{TunMTU: s.TunMTU, MSSMode: s.MSSMode, MSS: s.MSS}
}

func Validate(s *Settings) error {
	link := s.Link()
	if err := link.Validate(); err != nil {
		return err
	}
	s.MSSMode, s.MSS = link.MSSMode, link.MSS
	if err := vpnoptions.Domains(&s.DNSDomain, &s.DNSSearch); err != nil {
		return err
	}
	if s.DCO != "auto" && s.DCO != "off" {
		return fmt.Errorf("DCO mode must be auto or off")
	}
	if s.MaxClients < 1 || s.MaxClients > 65535 {
		return fmt.Errorf("Maximum connections must be between 1 and 65535")
	}
	if s.KeepaliveInterval < 1 || s.KeepaliveInterval > 3600 {
		return fmt.Errorf("Keepalive interval must be between 1 and 3600 seconds")
	}
	if s.KeepaliveTimeout < 2*s.KeepaliveInterval || s.KeepaliveTimeout > 86400 {
		return fmt.Errorf("Keepalive timeout must be at least twice the interval and at most 86400 seconds")
	}
	if _, err := netip.ParseAddr(s.Endpoint); err != nil {
		if len(s.Endpoint) > 253 || !regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`).MatchString(s.Endpoint) {
			return fmt.Errorf("VPN endpoint must be a hostname or IP address")
		}
	}
	if s.Port != 1194 {
		return fmt.Errorf("internal VPN port is fixed at 1194; configure host publication in Compose")
	}
	if s.ExternalPort < 1 || s.ExternalPort > 65535 {
		return fmt.Errorf("external port must be between 1 and 65535")
	}
	if s.Protocol != "udp" && s.Protocol != "tcp" {
		return fmt.Errorf("protocol must be udp or tcp")
	}
	prefix, err := netip.ParsePrefix(s.Network)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 1 || prefix.Bits() > 29 {
		return fmt.Errorf("VPN network must be an IPv4 CIDR prefix with length 1–29")
	}
	s.Network = prefix.Masked().String()
	if len(s.DNS) < 1 || len(s.DNS) > 8 {
		return fmt.Errorf("specify between 1 and 8 DNS servers")
	}
	for i, dns := range s.DNS {
		addr, err := netip.ParseAddr(strings.TrimSpace(dns))
		if err != nil || !addr.Is4() {
			return fmt.Errorf("DNS servers must be IPv4 addresses")
		}
		s.DNS[i] = addr.String()
	}
	if len(s.Routes) > 32 {
		return fmt.Errorf("at most 32 client routes are allowed")
	}
	if s.Routes == nil {
		s.Routes = []string{}
	}
	for i, route := range s.Routes {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(route))
		if err != nil || !prefix.Addr().Is4() {
			return fmt.Errorf("client routes must be IPv4 CIDR prefixes")
		}
		s.Routes[i] = prefix.Masked().String()
	}
	return nil
}

func (s *Service) Ensure(ctx context.Context, cfg config.Config) error {
	endpoint := ""
	if u, err := url.Parse(cfg.PublicURL); err == nil {
		endpoint = u.Hostname()
	}
	initial := Settings{Endpoint: endpoint, Port: 1194, ExternalPort: 1195, Protocol: "udp", Network: "10.8.0.0/24", DNS: []string{"172.16.0.1"}, Routes: []string{}, DCO: "auto", MaxClients: 1024, KeepaliveInterval: 10, KeepaliveTimeout: 60}
	if err := Validate(&initial); err != nil {
		return err
	}
	data, err := json.Marshal(initial)
	if err != nil {
		return err
	}
	if _, err := s.Store.DB.ExecContext(ctx, "INSERT INTO vpn_settings(id,configuration,revision,updated_at) VALUES (1,?,1,?) ON CONFLICT(id) DO NOTHING", string(data), time.Now().Unix()); err != nil {
		return err
	}
	return s.Publish(ctx)
}

func (s *Service) Get(ctx context.Context) (Settings, error) {
	// Missing fields in settings saved by older builds retain their old defaults.
	// Explicit zero values still fail validation.
	result := Settings{DCO: "auto", MaxClients: 1024, KeepaliveInterval: 10, KeepaliveTimeout: 60}
	var data string
	var revision int64
	if err := s.Store.DB.QueryRowContext(ctx, "SELECT configuration,revision FROM vpn_settings WHERE id=1").Scan(&data, &revision); err != nil {
		return result, err
	}
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return result, err
	}
	result.Revision = revision
	err := Validate(&result)
	return result, err
}

func (s *Service) Save(ctx context.Context, input Settings, actor string) (Settings, error) {
	s.Store.ConfigurationMu.Lock()
	defer s.Store.ConfigurationMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := Validate(&input); err != nil {
		return Settings{}, &pki.Error{Code: 400, Message: err.Error()}
	}
	if s.ValidateClients != nil {
		if err := s.ValidateClients(ctx, input.Network); err != nil {
			return Settings{}, err
		}
	}
	tx, err := s.Store.DB.BeginTx(ctx, nil)
	if err != nil {
		return Settings{}, err
	}
	defer tx.Rollback()
	var current int64
	if err := tx.QueryRowContext(ctx, "SELECT revision FROM vpn_settings WHERE id=1").Scan(&current); err != nil {
		return Settings{}, err
	}
	if current != input.Revision {
		return Settings{}, &pki.Error{Code: 409, Message: "VPN settings changed; refresh before saving"}
	}
	input.Revision++
	data, err := json.Marshal(input)
	if err != nil {
		return Settings{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE vpn_settings SET configuration=?,revision=?,updated_at=? WHERE id=1", string(data), input.Revision, time.Now().Unix()); err != nil {
		return Settings{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO audit_events(actor,action,target,created_at) VALUES (?,'vpn.settings.update',?,?)", actor, strconv.FormatInt(input.Revision, 10), time.Now().Unix()); err != nil {
		return Settings{}, err
	}
	if err := tx.Commit(); err != nil {
		return Settings{}, err
	}
	if err := s.publishLocked(ctx); err != nil {
		return input, fmt.Errorf("settings saved, publication pending: %w", err)
	}
	return input, nil
}

func (s *Service) Publish(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.publishLocked(ctx)
}
func (s *Service) publishLocked(ctx context.Context) error {
	if s.RuntimeDir == "" {
		return nil
	}
	v, err := s.Get(ctx)
	if err != nil {
		return err
	}
	data := []byte(fmt.Sprintf("DESK_REVISION=%d\nTUNNELSLATE_VPN_NETWORK=%s\nTUNNELSLATE_VPN_PORT=1194\nTUNNELSLATE_VPN_PROTOCOL=%s\nTUNNELSLATE_VPN_DNS=%s\nTUNNELSLATE_VPN_REDIRECT_GATEWAY=%t\nTUNNELSLATE_VPN_ROUTES=%s\n", v.Revision, v.Network, v.Protocol, strings.Join(v.DNS, ","), v.RedirectGateway, strings.Join(v.Routes, ",")))
	data = append(data, []byte(fmt.Sprintf("TUNNELSLATE_VPN_DNS_DOMAIN=%s\nTUNNELSLATE_VPN_DNS_SEARCH=%s\nTUNNELSLATE_VPN_TUN_MTU=%d\nTUNNELSLATE_VPN_MSS_MODE=%s\nTUNNELSLATE_VPN_MSS=%d\n", v.DNSDomain, strings.Join(v.DNSSearch, ","), v.TunMTU, v.MSSMode, v.MSS))...)
	path := filepath.Join(s.RuntimeDir, "settings.env")
	data = append(data, []byte(fmt.Sprintf("TUNNELSLATE_VPN_DCO=%s\nTUNNELSLATE_VPN_MAX_CLIENTS=%d\nTUNNELSLATE_VPN_KEEPALIVE_INTERVAL=%d\nTUNNELSLATE_VPN_KEEPALIVE_TIMEOUT=%d\n", v.DCO, v.MaxClients, v.KeepaliveInterval, v.KeepaliveTimeout))...)
	previous, err := os.ReadFile(path)
	if err == nil && bytes.Equal(previous, data) {
		return nil
	}
	// Publish per-device routes/DNS for the same desired revision before the
	// supervisor restarts OpenVPN with changed global settings.
	if s.PrepareClients != nil {
		if err := s.PrepareClients(ctx); err != nil {
			return err
		}
	}
	f, err := os.CreateTemp(s.RuntimeDir, ".settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
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
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(s.RuntimeDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (s *Service) AppliedRevision() int64 {
	data, err := os.ReadFile(filepath.Join(s.ControlDir, "applied-settings"))
	if err != nil {
		return 0
	}
	revision, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	return revision
}

type NetworkState struct {
	Pending     bool   `json:"pending"`
	Error       string `json:"error"`
	AppliedHash string `json:"-"`
}

func (s *Service) NetworkStatus() NetworkState {
	state := NetworkState{}
	data, err := os.ReadFile(filepath.Join(s.RuntimeDir, "network.json"))
	if err != nil {
		return state
	}
	applied, _ := os.ReadFile(filepath.Join(s.ControlDir, "applied-network"))
	state.AppliedHash = strings.TrimSpace(string(applied))
	state.Pending = state.AppliedHash != fmt.Sprintf("%x", sha256.Sum256(data))
	message, _ := os.ReadFile(filepath.Join(s.ControlDir, "network-error"))
	state.Error = strings.TrimSpace(string(message))
	state.Pending = state.Pending || state.Error != ""
	return state
}
