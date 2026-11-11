package vpnauth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"tunnelslate/internal/vpnauthwire"
)

type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string              { return e.Code }
func problem(status int, code string) error { return &Error{status, code} }

type Provider struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Kind      string         `json:"kind"`
	Enabled   bool           `json:"enabled"`
	Config    ProviderConfig `json:"config"`
	Secret    string         `json:"secret,omitempty"`
	HasSecret bool           `json:"has_secret"`
	Revision  int64          `json:"revision"`
}
type ProviderConfig struct {
	Address        string `json:"address"`
	BindDN         string `json:"bind_dn"`
	BaseDN         string `json:"base_dn"`
	UserFilter     string `json:"user_filter"`
	GroupDN        string `json:"group_dn"`
	GroupFilter    string `json:"group_filter"`
	CAPEM          string `json:"ca_pem"`
	NASIdentifier  string `json:"nas_identifier"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,128}$`)

func validateProvider(p *Provider) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 128 || strings.ContainsAny(p.Name, "\r\n\x00") {
		return problem(400, "vpn_auth.invalid_provider")
	}
	c := &p.Config
	if p.Kind == "ldap" {
		u, err := url.Parse(c.Address)
		if err != nil || u.Hostname() == "" || (u.Scheme != "ldaps" && u.Scheme != "ldap") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return problem(400, "vpn_auth.invalid_ldap")
		}
		if c.BindDN == "" || c.BaseDN == "" || len(c.BindDN) > 1024 || len(c.BaseDN) > 1024 || len(c.GroupDN) > 1024 {
			return problem(400, "vpn_auth.invalid_ldap")
		}
		if _, err = ldap.ParseDN(c.BindDN); err != nil {
			return problem(400, "vpn_auth.invalid_ldap")
		}
		if _, err = ldap.ParseDN(c.BaseDN); err != nil {
			return problem(400, "vpn_auth.invalid_ldap")
		}
		if strings.Count(c.UserFilter, "{username}") != 1 || len(c.UserFilter) > 2048 {
			return problem(400, "vpn_auth.invalid_filter")
		}
		if _, err = ldap.CompileFilter(strings.ReplaceAll(c.UserFilter, "{username}", "test")); err != nil {
			return problem(400, "vpn_auth.invalid_filter")
		}
		if c.GroupDN != "" {
			if _, err = ldap.ParseDN(c.GroupDN); err != nil {
				return problem(400, "vpn_auth.invalid_ldap")
			}
			if c.GroupFilter == "" {
				c.GroupFilter = "(member={dn})"
			}
			if (!strings.Contains(c.GroupFilter, "{dn}") && !strings.Contains(c.GroupFilter, "{username}")) || len(c.GroupFilter) > 2048 {
				return problem(400, "vpn_auth.invalid_filter")
			}
			if _, err = ldap.CompileFilter(strings.NewReplacer("{dn}", "test", "{username}", "test").Replace(c.GroupFilter)); err != nil {
				return problem(400, "vpn_auth.invalid_filter")
			}
		}
		if _, err = tlsConfig(*c); err != nil {
			return problem(400, "vpn_auth.invalid_ca")
		}
	} else if p.Kind == "radius" {
		if c.TimeoutSeconds == 0 {
			c.TimeoutSeconds = vpnauthwire.DefaultRADIUSTimeoutSeconds
		}
		if c.TimeoutSeconds < 5 || c.TimeoutSeconds > vpnauthwire.MaxRADIUSTimeoutSeconds {
			return problem(400, "vpn_auth.invalid_radius_timeout")
		}
		host, port, err := net.SplitHostPort(c.Address)
		n, e := strconv.Atoi(port)
		if err != nil || host == "" || e != nil || n < 1 || n > 65535 || strings.ContainsAny(host, " /\r\n\x00") {
			return problem(400, "vpn_auth.invalid_radius")
		}
		if len(c.NASIdentifier) > 128 || strings.ContainsAny(c.NASIdentifier, "\r\n\x00") {
			return problem(400, "vpn_auth.invalid_radius")
		}
	} else {
		return problem(400, "vpn_auth.invalid_provider")
	}
	if len(p.Secret) > 4096 || strings.ContainsRune(p.Secret, 0) {
		return problem(400, "vpn_auth.invalid_secret")
	}
	return nil
}

func providerTimeout(p Provider) time.Duration {
	if p.Kind != "radius" {
		return 10 * time.Second
	}
	seconds := p.Config.TimeoutSeconds
	if seconds == 0 {
		seconds = vpnauthwire.DefaultRADIUSTimeoutSeconds
	}
	if seconds < 5 || seconds > vpnauthwire.MaxRADIUSTimeoutSeconds {
		// Invalid persisted configuration must not create an unbounded wait.
		return 0
	}
	return time.Duration(seconds) * time.Second
}
func tlsConfig(c ProviderConfig) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAPEM != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(c.CAPEM)) {
			return nil, errors.New("invalid CA certificate")
		}
		config.RootCAs = roots
	}
	u, err := url.Parse(c.Address)
	if err == nil {
		config.ServerName = u.Hostname()
	}
	return config, nil
}
