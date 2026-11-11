// Package vpnoptions contains shared, validated DNS and tunnel parameters.
package vpnoptions

import (
	"fmt"
	"regexp"
	"strings"
)

var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Domains accepts ASCII DNS names (including punycode), never config fragments.
func Domains(domain *string, search *[]string) error {
	normalize := func(value string) (string, error) {
		value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
		if value == "" || len(value) > 253 {
			return "", fmt.Errorf("DNS domains must be valid names using ASCII letters, digits and hyphens")
		}
		for _, label := range strings.Split(value, ".") {
			if !domainLabel.MatchString(label) {
				return "", fmt.Errorf("DNS domains must be valid names using ASCII letters, digits and hyphens")
			}
		}
		return value, nil
	}
	if strings.TrimSpace(*domain) != "" {
		value, err := normalize(*domain)
		if err != nil {
			return err
		}
		*domain = value
	} else {
		*domain = ""
	}
	if len(*search) > 10 {
		return fmt.Errorf("At most 10 DNS search domains are allowed")
	}
	values := []string{}
	seen := map[string]bool{}
	for _, value := range *search {
		value, err := normalize(value)
		if err != nil {
			return err
		}
		if !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	*search = values
	return nil
}

type Link struct {
	TunMTU  int    `json:"tun_mtu"`
	MSSMode string `json:"mss_mode"`
	MSS     int    `json:"mss"`
}

func (v *Link) Validate() error {
	if v.MSSMode == "" {
		v.MSSMode = "default"
	}
	if v.TunMTU != 0 && (v.TunMTU < 576 || v.TunMTU > 1500) {
		return fmt.Errorf("Tunnel MTU must be default or between 576 and 1500 bytes")
	}
	if v.MSSMode != "default" && v.MSSMode != "custom" && v.MSSMode != "off" {
		return fmt.Errorf("MSS mode must be default, custom or off")
	}
	mtu := v.TunMTU
	if mtu == 0 {
		mtu = 1500
	}
	if v.MSSMode == "custom" {
		if v.MSS < 536 || v.MSS > mtu-40 {
			return fmt.Errorf("TCP MSS must be between 536 and tunnel MTU minus 40 bytes")
		}
	} else {
		v.MSS = 0
	}
	return nil
}

// Directives supplies downloaded profiles. Custom MSS is applied by the server
// kernel in both directions, including DCO traffic. Disable userspace mssfix to
// avoid a second, cipher-dependent limit and preserve older client compatibility.
func (v Link) Directives(protocol string) string {
	var b strings.Builder
	if v.TunMTU != 0 {
		fmt.Fprintf(&b, "tun-mtu %d\n", v.TunMTU)
	}
	if protocol == "udp" {
		switch v.MSSMode {
		case "custom":
			fmt.Fprintf(&b, "# TCP MSS limited to %d bytes by the server\nmssfix 0\n", v.MSS)
		case "off":
			b.WriteString("mssfix 0\n")
		}
	}
	return b.String()
}
