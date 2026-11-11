package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"tunnelslate/internal/branding"
)

// Fixed container layout. Host bind paths and network publication belong to Compose.
const (
	DefaultStatsRetentionDays = 90
	DefaultAuditRetentionDays = 365
	MaxAuditRetentionDays     = 36500
	// DatabasePath is also used by offline console recovery commands.
	DatabasePath     = "/data/app/desk.sqlite"
	listen           = ":8080"
	webDirectory     = "/app/web"
	pkiDirectory     = "/data/pki"
	openvpnDirectory = "/data/openvpn"
	ccdDirectory     = "/data/ccd"
	managementSocket = "/run/tunnelslate/management.sock"
)

type Config struct {
	Listen, DBPath, WebDir, PKIDir, OpenVPNDir, CCDDir string
	ManagementSocket                                   string
	MetricsListen                                      string
	PublicURL, BasePath                                string
	CookieSecure                                       bool
	SessionTTL                                         time.Duration
	TrustedProxies                                     []netip.Prefix
	AuditRetentionDays                                 int
	StatsRetentionDays                                 int
}

func env(key, fallback string) string {
	if v := os.Getenv(branding.EnvPrefix + key); v != "" {
		return v
	}
	return fallback
}

func Load() (Config, error) {
	c := Config{
		Listen: listen, DBPath: DatabasePath,
		WebDir: webDirectory, PKIDir: pkiDirectory,
		OpenVPNDir: openvpnDirectory, CCDDir: ccdDirectory,
		PublicURL: env("PUBLIC_URL", "http://localhost:8090"),
	}
	c.ManagementSocket = managementSocket
	for _, raw := range strings.Split(env("TRUSTED_PROXIES", ""), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			ip, ipErr := netip.ParseAddr(raw)
			if ipErr != nil || ip.Zone() != "" {
				return c, errors.New("TRUSTED_PROXIES must contain comma-separated IP addresses or CIDRs")
			}
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		c.TrustedProxies = append(c.TrustedProxies, prefix.Masked())
	}
	var err error
	if c.CookieSecure, err = strconv.ParseBool(env("COOKIE_SECURE", "true")); err != nil {
		return c, fmt.Errorf("COOKIE_SECURE: %w", err)
	}
	if c.SessionTTL, err = time.ParseDuration(env("SESSION_TTL", "12h")); err != nil || c.SessionTTL < time.Minute || c.SessionTTL > 7*24*time.Hour {
		return c, errors.New("SESSION_TTL must be between 1m and 168h")
	}
	if c.AuditRetentionDays, err = strconv.Atoi(env("AUDIT_RETENTION_DAYS", strconv.Itoa(DefaultAuditRetentionDays))); err != nil || c.AuditRetentionDays < 1 || c.AuditRetentionDays > MaxAuditRetentionDays {
		return c, errors.New("AUDIT_RETENTION_DAYS must be an integer between 1 and 36500")
	}
	if c.StatsRetentionDays, err = strconv.Atoi(env("STATS_RETENTION_DAYS", strconv.Itoa(DefaultStatsRetentionDays))); err != nil || c.StatsRetentionDays < 1 || c.StatsRetentionDays > MaxAuditRetentionDays {
		return c, errors.New("STATS_RETENTION_DAYS must be an integer between 1 and 36500")
	}

	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return c, errors.New("PUBLIC_URL must be an HTTP(S) origin without a path")
	}
	c.PublicURL = u.Scheme + "://" + u.Host
	c.BasePath = env("BASE_PATH", "")
	if strings.Contains(c.BasePath, "//") {
		return c, errors.New("BASE_PATH must not contain empty path segments")
	}
	c.BasePath = strings.TrimSuffix(c.BasePath, "/")
	if !regexp.MustCompile(`^(/[a-zA-Z0-9_-][a-zA-Z0-9_.-]*)*$`).MatchString(c.BasePath) {
		return c, errors.New("BASE_PATH must be an absolute URL path such as /ovpn, without query, escapes or dot segments")
	}
	if c.CookieSecure && u.Scheme != "https" {
		return c, errors.New("COOKIE_SECURE=true requires an HTTPS PUBLIC_URL")
	}
	return c, nil
}
