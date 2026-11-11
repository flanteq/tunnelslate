package config

import (
	"testing"
)

func TestConfigRejectsInvalidDeployment(t *testing.T) {
	t.Setenv("TUNNELSLATE_COOKIE_SECURE", "false")
	for _, tc := range []struct{ key, value string }{
		{"SESSION_TTL", "0s"}, {"PUBLIC_URL", "https://example.test/path"},
		{"TRUSTED_PROXIES", "proxy.example.com"}, {"TRUSTED_PROXIES", "192.0.2.10/99"},
		{"BASE_PATH", "ovpn"}, {"BASE_PATH", "/ovpn/../admin"}, {"BASE_PATH", "/ovpn//admin"}, {"BASE_PATH", "/ovpn?x=1"}, {"BASE_PATH", "/%6fvpn"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			t.Setenv("TUNNELSLATE_"+tc.key, tc.value)
			if _, err := Load(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestTrustedProxies(t *testing.T) {
	t.Setenv("TUNNELSLATE_COOKIE_SECURE", "false")
	t.Setenv("TUNNELSLATE_TRUSTED_PROXIES", "192.0.2.10, 198.51.100.7/24, 2001:db8::1")
	cfg, err := Load()
	if err != nil || len(cfg.TrustedProxies) != 3 {
		t.Fatalf("trusted proxies: %v %v", cfg.TrustedProxies, err)
	}
	for i, want := range []string{"192.0.2.10/32", "198.51.100.0/24", "2001:db8::1/128"} {
		if cfg.TrustedProxies[i].String() != want {
			t.Fatalf("proxy %d: %s", i, cfg.TrustedProxies[i])
		}
	}
}

func TestAuditRetentionDays(t *testing.T) {
	t.Setenv("TUNNELSLATE_COOKIE_SECURE", "false")
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{"", 365}, {"1", 1}, {"90", 90}, {"365", 365}, {"36500", 36500},
	} {
		t.Setenv("TUNNELSLATE_AUDIT_RETENTION_DAYS", tc.raw)
		cfg, err := Load()
		if err != nil || cfg.AuditRetentionDays != tc.want {
			t.Fatalf("retention %q: days=%d err=%v", tc.raw, cfg.AuditRetentionDays, err)
		}
	}
	for _, raw := range []string{"0", "-1", "36501", "1.5", "365d", "garbage", "99999999999999999999999"} {
		t.Setenv("TUNNELSLATE_AUDIT_RETENTION_DAYS", raw)
		if _, err := Load(); err == nil {
			t.Fatalf("invalid retention accepted: %q", raw)
		}
	}
}

func TestStatsRetentionDays(t *testing.T) {
	t.Setenv("TUNNELSLATE_COOKIE_SECURE", "false")
	for _, raw := range []string{"", "1", "90", "36500"} {
		t.Setenv("TUNNELSLATE_STATS_RETENTION_DAYS", raw)
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if raw == "" && c.StatsRetentionDays != 90 {
			t.Fatal("wrong default")
		}
		if c.AuditRetentionDays != 365 {
			t.Fatal("statistics changed audit retention")
		}
	}
	for _, raw := range []string{"0", "-1", "36501", "1.5", "abc"} {
		t.Setenv("TUNNELSLATE_STATS_RETENTION_DAYS", raw)
		if _, err := Load(); err == nil {
			t.Fatal("invalid retention accepted", raw)
		}
	}
}

func TestBasePathNormalized(t *testing.T) {
	t.Setenv("TUNNELSLATE_COOKIE_SECURE", "false")
	for input, want := range map[string]string{"": "", "/": "", "/ovpn": "/ovpn", "/ovpn/": "/ovpn", "/control/ovpn": "/control/ovpn"} {
		t.Setenv("TUNNELSLATE_BASE_PATH", input)
		cfg, err := Load()
		if err != nil || cfg.BasePath != want {
			t.Fatalf("%s: path=%s err=%v", input, cfg.BasePath, err)
		}
	}
}

func TestSecureOrigin(t *testing.T) {
	t.Setenv("TUNNELSLATE_PUBLIC_URL", "https://desk.test")
	t.Setenv("TUNNELSLATE_COOKIE_SECURE", "true")
	_, err := Load()
	if err != nil {
		t.Fatalf("secure origin: %v", err)
	}
}

func TestContainerLayoutCannotBeOverriddenByEnvironment(t *testing.T) {
	t.Setenv("TUNNELSLATE_COOKIE_SECURE", "false")
	for _, name := range []string{"LISTEN", "DB_PATH", "WEB_DIR", "PKI_DIR", "OPENVPN_DIR", "CCD_DIR", "MGMT_SOCKET"} {
		t.Setenv("TUNNELSLATE_"+name, "unexpected-override")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" || cfg.DBPath != "/data/app/desk.sqlite" || cfg.WebDir != "/app/web" || cfg.PKIDir != "/data/pki" || cfg.OpenVPNDir != "/data/openvpn" || cfg.CCDDir != "/data/ccd" || cfg.ManagementSocket != "/run/tunnelslate/management.sock" {
		t.Fatal("environment changed the fixed container layout")
	}
}
