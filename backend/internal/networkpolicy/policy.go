// Package networkpolicy describes the data shared by the panel and VPN helper.
// It never accepts raw firewall commands or OpenVPN directives.
package networkpolicy

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

type Device struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	ClientName string   `json:"client_name"`
	CNs        []string `json:"cns"`
	IP         string   `json:"static_ip"`
	Sites      []string `json:"site_networks"`
	Access     string   `json:"access_mode"`
	Allowed    []string `json:"allowed_networks"`
	DNS        []string `json:"dns"`
}

type Policy struct {
	Revision   int64    `json:"revision"`
	Network    string   `json:"network"`
	Isolate    bool     `json:"isolate_clients"`
	SiteToSite bool     `json:"site_to_site"`
	SiteNAT    bool     `json:"site_nat"`
	Devices    []Device `json:"devices"`
}

func Prefixes(values *[]string, max int, sites bool) error {
	if len(*values) > max {
		return fmt.Errorf("Too many network prefixes")
	}
	normalized := []string{}
	seen := map[string]bool{}
	for _, value := range *values {
		p, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || !p.Addr().Is4() {
			return fmt.Errorf("Networks must be IPv4 CIDR prefixes")
		}
		p = p.Masked()
		if sites {
			for _, reserved := range []string{"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"} {
				if p.Overlaps(netip.MustParsePrefix(reserved)) {
					return fmt.Errorf("Site networks must be unicast IPv4 subnets")
				}
			}
		}
		if !seen[p.String()] {
			normalized = append(normalized, p.String())
			seen[p.String()] = true
		}
	}
	*values = normalized
	return nil
}

func DeviceOptions(d *Device, network string) error {
	if d.Access == "" {
		d.Access = "all"
	}
	if d.Access != "all" && d.Access != "restricted" {
		return fmt.Errorf("Access mode must be all or restricted")
	}
	if err := Prefixes(&d.Sites, 16, true); err != nil {
		return err
	}
	if err := Prefixes(&d.Allowed, 32, false); err != nil {
		return err
	}
	if d.Access == "all" {
		d.Allowed = []string{}
	}
	vpn, err := netip.ParsePrefix(network)
	if err != nil || !vpn.Addr().Is4() {
		return fmt.Errorf("Invalid VPN network")
	}
	for i, site := range d.Sites {
		p := netip.MustParsePrefix(site)
		if vpn.Overlaps(p) {
			return fmt.Errorf("Site networks overlap the VPN network or another site")
		}
		for _, other := range d.Sites[:i] {
			if p.Overlaps(netip.MustParsePrefix(other)) {
				return fmt.Errorf("Site networks overlap the VPN network or another site")
			}
		}
	}
	if (d.Access == "restricted" || len(d.Sites) > 0) && d.IP == "" {
		return fmt.Errorf("Network policies require a fixed VPN address")
	}
	return nil
}

var commonName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func (p *Policy) Validate() error {
	vpn, err := netip.ParsePrefix(p.Network)
	if err != nil || !vpn.Addr().Is4() || vpn.Bits() < 1 || vpn.Bits() > 29 || p.Revision < 1 {
		return fmt.Errorf("Invalid network policy")
	}
	p.Network = vpn.Masked().String()
	vpn = vpn.Masked()
	total := 0
	ips := map[string]bool{}
	cns := map[string]bool{}
	sites := []netip.Prefix{}
	for i := range p.Devices {
		d := &p.Devices[i]
		if err := DeviceOptions(d, p.Network); err != nil {
			return err
		}
		if d.IP != "" {
			ip, err := netip.ParseAddr(d.IP)
			if err != nil || !ip.Is4() || !vpn.Contains(ip) || ip == vpn.Addr() || ip == vpn.Addr().Next() || ips[d.IP] {
				return fmt.Errorf("Invalid or duplicate fixed VPN address")
			}
			ips[d.IP] = true
		}
		for _, cn := range d.CNs {
			if !commonName.MatchString(cn) || cns[cn] {
				return fmt.Errorf("Invalid or duplicate peer identity")
			}
			cns[cn] = true
		}
		for _, dns := range d.DNS {
			ip, err := netip.ParseAddr(dns)
			if err != nil || !ip.Is4() {
				return fmt.Errorf("Invalid DNS address in network policy")
			}
		}
		for _, site := range d.Sites {
			prefix := netip.MustParsePrefix(site)
			for _, other := range sites {
				if prefix.Overlaps(other) {
					return fmt.Errorf("Site networks overlap the VPN network or another site")
				}
			}
			sites = append(sites, prefix)
			total++
		}
		sort.Strings(d.CNs)
	}
	if total > 256 {
		return fmt.Errorf("At most 256 site networks are allowed")
	}
	sort.Slice(p.Devices, func(i, j int) bool { return p.Devices[i].ID < p.Devices[j].ID })
	if p.Devices == nil {
		p.Devices = []Device{}
	}
	return nil
}

// Learn permits only the address actually assigned to this connection and the
// subnets explicitly delegated to its certificate. Dynamic learning cannot take
// ownership of another device's VPN address or LAN, even while it is offline.
func (p Policy) Learn(address, cn, assigned string) bool {
	ip, err := netip.ParseAddr(address)
	fixed := ""
	for _, d := range p.Devices {
		if contains(d.CNs, cn) {
			fixed = d.IP
			break
		}
	}
	if err == nil && ip.Is4() && ip.String() == assigned {
		if fixed != "" {
			return ip.String() == fixed
		}
		vpn := netip.MustParsePrefix(p.Network)
		return netip.PrefixFrom(vpn.Addr(), vpn.Bits()+1).Contains(ip) && ip != vpn.Addr() && ip != vpn.Addr().Next()
	}
	if !p.SiteToSite {
		return false
	}
	for _, d := range p.Devices {
		if !contains(d.CNs, cn) {
			continue
		}
		for _, site := range d.Sites {
			prefix := netip.MustParsePrefix(site)
			if err == nil && prefix.Contains(ip) {
				return true
			}
			if network, e := netip.ParsePrefix(address); e == nil && network.Masked() == prefix {
				return true
			}
		}
	}
	return false
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// Rules only owns DESK_NET_* chains. Match both directions without a blanket
// ESTABLISHED exemption, so an existing TCP connection cannot bypass a new ACL.
func (p Policy) Rules(egress string) string {
	var b strings.Builder
	b.WriteString("*filter\n:DESK_NET_FWD - [0:0]\n:DESK_NET_FROM - [0:0]\n:DESK_NET_TO - [0:0]\n-F DESK_NET_FWD\n-F DESK_NET_FROM\n-F DESK_NET_TO\n")
	if p.Isolate {
		b.WriteString("-A DESK_NET_FWD -i tun+ -o tun+ -j DROP\n")
	}
	for _, d := range p.Devices {
		for _, site := range d.Sites {
			// Never let a disconnected site's packets escape over the default route.
			fmt.Fprintf(&b, "-A DESK_NET_FWD -d %s ! -o tun+ -j DROP\n", site)
			if !p.SiteToSite {
				fmt.Fprintf(&b, "-A DESK_NET_FROM -s %s -j DROP\n-A DESK_NET_TO -d %s -j DROP\n", site, site)
			}
		}
	}
	b.WriteString("-A DESK_NET_FWD -i tun+ -j DESK_NET_FROM\n-A DESK_NET_FWD -o tun+ -j DESK_NET_TO\n")
	for i, d := range p.Devices {
		sources := append([]string{}, d.Sites...)
		if d.IP != "" {
			sources = append(sources, d.IP+"/32")
		}
		if len(d.CNs) == 0 {
			for _, source := range sources {
				fmt.Fprintf(&b, "-A DESK_NET_FROM -s %s -j DROP\n-A DESK_NET_TO -d %s -j DROP\n", source, source)
			}
			continue
		}
		if d.Access != "restricted" {
			continue
		}
		from, to := fmt.Sprintf("DESK_NET_S%d", i), fmt.Sprintf("DESK_NET_D%d", i)
		fmt.Fprintf(&b, ":%s - [0:0]\n:%s - [0:0]\n-F %s\n-F %s\n", from, to, from, to)
		for _, source := range sources {
			fmt.Fprintf(&b, "-A DESK_NET_FROM -s %s -j %s\n-A DESK_NET_TO -d %s -j %s\n", source, from, source, to)
		}
		for _, allowed := range d.Allowed {
			fmt.Fprintf(&b, "-A %s -d %s -j RETURN\n-A %s -s %s -j RETURN\n", from, allowed, to, allowed)
		}
		for _, dns := range d.DNS {
			for _, proto := range []string{"udp", "tcp"} {
				fmt.Fprintf(&b, "-A %s -d %s -p %s --dport 53 -j RETURN\n-A %s -s %s -p %s --sport 53 -m conntrack --ctstate ESTABLISHED -j RETURN\n", from, dns, proto, to, dns, proto)
			}
		}
		fmt.Fprintf(&b, "-A %s -j DROP\n-A %s -j DROP\n", from, to)
	}
	b.WriteString("COMMIT\n*nat\n:DESK_NET_NAT - [0:0]\n-F DESK_NET_NAT\n")
	if p.SiteToSite && p.SiteNAT {
		for _, d := range p.Devices {
			if len(d.CNs) > 0 {
				for _, site := range d.Sites {
					fmt.Fprintf(&b, "-A DESK_NET_NAT -s %s -o %s -j MASQUERADE\n", site, egress)
				}
			}
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

func Mask(p netip.Prefix) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ^uint32(0)<<(32-p.Bits()))
	return netip.AddrFrom4(b).String()
}
