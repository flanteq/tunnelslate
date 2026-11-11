package vpnsettings

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tunnelslate/internal/config"
	"tunnelslate/internal/store"
)

func TestSettingsPersistValidateAndPublish(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(root, "desk.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.DB.Close()
	s := &Service{Store: db, RuntimeDir: root}
	if err := s.Ensure(ctx, config.Config{PublicURL: "https://control.test"}); err != nil {
		t.Fatal(err)
	}
	v, err := s.Get(ctx)
	if err != nil || v.Endpoint != "control.test" || v.Revision != 1 {
		t.Fatalf("settings=%+v err=%v", v, err)
	}
	v.Network = "172.27.13.42/23"
	v.DNS = []string{"172.16.0.1", "1.1.1.1"}
	v.Protocol = "tcp"
	v.DNSDomain = "OFFICE.example.com."
	v.DNSSearch = []string{"dev.example.com", "DEV.example.com."}
	v.TunMTU, v.MSSMode, v.MSS = 1400, "custom", 1320
	v.RedirectGateway = true
	v.Routes = []string{"192.168.13.42/24"}
	v.DCO, v.MaxClients, v.KeepaliveInterval, v.KeepaliveTimeout = "off", 25, 15, 90
	saved, err := s.Save(ctx, v, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 2 || saved.Network != "172.27.12.0/23" || saved.Routes[0] != "192.168.13.0/24" {
		t.Fatal("normalization or revision failed")
	}
	if _, err := s.Save(ctx, v, "admin"); err == nil {
		t.Fatal("stale revision overwrote newer settings")
	}
	data, err := os.ReadFile(filepath.Join(root, "settings.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"TUNNELSLATE_VPN_DNS_DOMAIN=office.example.com", "TUNNELSLATE_VPN_DNS_SEARCH=dev.example.com", "TUNNELSLATE_VPN_TUN_MTU=1400", "TUNNELSLATE_VPN_MSS_MODE=custom", "TUNNELSLATE_VPN_MSS=1320", "DESK_REVISION=2", "TUNNELSLATE_VPN_PROTOCOL=tcp", "TUNNELSLATE_VPN_REDIRECT_GATEWAY=true", "TUNNELSLATE_VPN_DNS=172.16.0.1,1.1.1.1", "TUNNELSLATE_VPN_DCO=off", "TUNNELSLATE_VPN_MAX_CLIENTS=25", "TUNNELSLATE_VPN_KEEPALIVE_INTERVAL=15", "TUNNELSLATE_VPN_KEEPALIVE_TIMEOUT=90"} {
		if !strings.Contains(string(data), line) {
			t.Fatal("setting not published:", line)
		}
	}
	before, err := os.Stat(filepath.Join(root, "settings.env"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(root, "settings.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("unchanged settings file replaced, causing unnecessary VPN restart")
	}
	// Changed deployment defaults never overwrite saved settings on restart.
	if err := s.Ensure(ctx, config.Config{PublicURL: "https://changed.test"}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := s.Get(ctx)
	if err != nil || reloaded.Revision != 2 || reloaded.Endpoint != "control.test" || reloaded.DNSDomain != "office.example.com" || len(reloaded.DNSSearch) != 1 || reloaded.TunMTU != 1400 || reloaded.MSSMode != "custom" || reloaded.MSS != 1320 || reloaded.DCO != "off" || reloaded.MaxClients != 25 || reloaded.KeepaliveInterval != 15 || reloaded.KeepaliveTimeout != 90 {
		t.Fatal("restart reset settings")
	}
}

func TestSettingsRejectInvalidValues(t *testing.T) {
	valid := Settings{Endpoint: "vpn.test", Port: 1194, ExternalPort: 1195, Protocol: "udp", Network: "10.8.0.0/24", DNS: []string{"172.16.0.1"}, DCO: "auto", MaxClients: 1024, KeepaliveInterval: 10, KeepaliveTimeout: 60}
	for _, change := range []func(*Settings){
		func(v *Settings) { v.Endpoint = "vpn.test\nscript-security 2" },
		func(v *Settings) { v.Network = "::/64" },
		func(v *Settings) { v.Protocol = "udp;id" },
		func(v *Settings) { v.DNS = []string{"1.1.1.999"} },
		func(v *Settings) { v.Routes = []string{"192.168.1.0/33"} },
		func(v *Settings) { v.ExternalPort = 0 },
		func(v *Settings) { v.Port = 1294 },
		func(v *Settings) { v.DCO = "auto\ndisable-dco" },
		func(v *Settings) { v.MaxClients = 0 },
		func(v *Settings) { v.MaxClients = 65536 },
		func(v *Settings) { v.KeepaliveInterval = 0 },
		func(v *Settings) { v.KeepaliveInterval = 3601 },
		func(v *Settings) { v.KeepaliveTimeout = 19 },
		func(v *Settings) { v.KeepaliveTimeout = 86401 },
	} {
		v := valid
		change(&v)
		if Validate(&v) == nil {
			t.Fatalf("invalid setting accepted: %+v", v)
		}
	}
}

func TestLegacySettingsKeepDefaultsWithoutResettingSavedValues(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(root, "desk.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.DB.Close()
	s := &Service{Store: db, RuntimeDir: root}
	if err := s.Ensure(ctx, config.Config{PublicURL: "https://vpn.test"}); err != nil {
		t.Fatal(err)
	}
	legacy := `{"endpoint":"existing.test","port":1194,"external_port":443,"protocol":"tcp","network":"10.9.0.0/24","dns":["192.0.2.53"],"routes":[],"redirect_gateway":true}`
	if _, err := db.DB.ExecContext(ctx, "UPDATE vpn_settings SET configuration=?,revision=7 WHERE id=1", legacy); err != nil {
		t.Fatal(err)
	}
	if err := s.Ensure(ctx, config.Config{PublicURL: "https://changed.test"}); err != nil {
		t.Fatal(err)
	}
	v, err := s.Get(ctx)
	if err != nil || v.Endpoint != "existing.test" || v.ExternalPort != 443 || v.Protocol != "tcp" || v.Revision != 7 || v.DNSDomain != "" || len(v.DNSSearch) != 0 || v.TunMTU != 0 || v.MSSMode != "default" || v.MSS != 0 || v.DCO != "auto" || v.MaxClients != 1024 || v.KeepaliveInterval != 10 || v.KeepaliveTimeout != 60 {
		t.Fatalf("legacy settings=%+v err=%v", v, err)
	}
	if _, err := db.DB.ExecContext(ctx, "UPDATE vpn_settings SET configuration=? WHERE id=1", strings.TrimSuffix(legacy, "}")+`,"max_clients":0}`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx); err == nil {
		t.Fatal("explicit invalid value was silently replaced by a default")
	}
}

func TestNetworkApplicationRequiresCurrentPolicyDigest(t *testing.T) {
	root := t.TempDir()
	s := Service{RuntimeDir: root, ControlDir: root}
	body := []byte(`{"revision":1,"network":"10.8.0.0/24","devices":[]}`)
	if err := os.WriteFile(filepath.Join(root, "network.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	if !s.NetworkStatus().Pending {
		t.Fatal("missing acknowledgment reported as applied")
	}
	if err := os.WriteFile(filepath.Join(root, "applied-network"), []byte(fmt.Sprintf("%x\n", sha256.Sum256(body))), 0600); err != nil {
		t.Fatal(err)
	}
	if s.NetworkStatus().Pending {
		t.Fatal("matching acknowledgment not accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "network.json"), append(body, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "network-error"), []byte("Site network overlaps container network\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Restoring an earlier configuration must not reuse its stale acknowledgment
	// while the supervisor is still reporting a failed apply.
	if err := os.WriteFile(filepath.Join(root, "network.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	state := s.NetworkStatus()
	if !state.Pending || state.Error != "Site network overlaps container network" {
		t.Fatal(state)
	}
}
