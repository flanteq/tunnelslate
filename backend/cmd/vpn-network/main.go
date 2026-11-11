// vpn-network runs only inside the VPN container. It owns firewall chains in
// that container's network namespace and validates all published policy data.
package main

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"time"

	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"tunnelslate/internal/management"

	"tunnelslate/internal/networkpolicy"
)

const activePolicy = "/run/openvpn/network.json"
const desiredPolicy = "/etc/openvpn/runtime/network.json"

func load(path string) (networkpolicy.Policy, []byte, error) {
	var p networkpolicy.Policy
	data, err := os.ReadFile(path)
	if err != nil {
		return p, nil, err
	}
	if len(data) > 4*1024*1024 {
		return p, nil, fmt.Errorf("Network policy is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&p); err != nil {
		return p, nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return p, nil, fmt.Errorf("Invalid network policy JSON")
	}
	return p, data, p.Validate()
}

func command(name string, args ...string) error {
	c := exec.Command(name, args...)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func hook(table, chain string, args ...string) error {
	check := append([]string{"-w", "5", "-t", table, "-C", chain}, args...)
	if exec.Command("iptables", check...).Run() == nil {
		return nil
	}
	add := append([]string{"-w", "5", "-t", table, "-I", chain, "1"}, args...)
	return command("iptables", add...)
}

func validateRuntime(p networkpolicy.Policy, egress string) error {
	if !regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`).MatchString(egress) {
		return fmt.Errorf("Invalid outgoing interface")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, "tun") || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			local, err := netip.ParsePrefix(addr.String())
			if err != nil || !local.Addr().Is4() {
				continue
			}
			for _, d := range p.Devices {
				for _, site := range d.Sites {
					if local.Overlaps(netip.MustParsePrefix(site)) {
						return fmt.Errorf("Site network %s overlaps container network %s", site, local.Masked())
					}
				}
			}
		}
	}
	return nil
}

func apply(p networkpolicy.Policy, egress string) error {
	if err := validateRuntime(p, egress); err != nil {
		return err
	}
	// Each table is committed atomically, including rules for established flows.
	// Only project-owned chains are replaced; the OpenVPN process stays running.
	c := exec.Command("iptables-restore", "--wait", "5", "--noflush")
	c.Stdin = strings.NewReader(p.Rules(egress))
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("Apply network policy: %w: %s", err, out)
	}
	for _, h := range []struct {
		chain string
		args  []string
	}{
		{"FORWARD", []string{"-j", "DESK_NET_FWD"}},
		{"INPUT", []string{"-i", "tun+", "-j", "DESK_NET_FROM"}},
		{"OUTPUT", []string{"-o", "tun+", "-j", "DESK_NET_TO"}},
	} {
		if err := hook("filter", h.chain, h.args...); err != nil {
			return err
		}
	}
	return hook("nat", "POSTROUTING", "-j", "DESK_NET_NAT")
}

// Reconnect only peers whose address or delegated source networks changed.
// ACL and DNS changes are enforced by the firewall without touching sessions.
func changedPeers(previous, next networkpolicy.Policy) []string {
	old := map[string]networkpolicy.Device{}
	current := map[string]networkpolicy.Device{}
	for _, d := range previous.Devices {
		for _, cn := range d.CNs {
			old[cn] = d
		}
	}
	for _, d := range next.Devices {
		for _, cn := range d.CNs {
			current[cn] = d
		}
	}
	result := []string{}
	seen := map[string]bool{}
	for _, entries := range []map[string]networkpolicy.Device{old, current} {
		for cn := range entries {
			a, aOK := old[cn]
			b, bOK := current[cn]
			if (!aOK || !bOK || a.IP != b.IP || !reflect.DeepEqual(a.Sites, b.Sites) || previous.SiteToSite != next.SiteToSite) && !seen[cn] {
				result = append(result, cn)
				seen[cn] = true
			}
		}
	}
	return result
}

// A different device's pending update must not reject an unrelated handshake.
func peerUnchanged(active, desired networkpolicy.Policy, cn string) bool {
	if active.Revision != desired.Revision || active.Network != desired.Network {
		return false
	}
	peer := func(p networkpolicy.Policy) (networkpolicy.Device, bool) {
		for _, d := range p.Devices {
			for _, name := range d.CNs {
				if name == cn {
					d.Name = ""
					d.ClientName = ""
					return d, true
				}
			}
		}
		return networkpolicy.Device{}, false
	}
	a, aOK := peer(active)
	b, bOK := peer(desired)
	return aOK == bOK && reflect.DeepEqual(a, b)
}

// Fallback routes deliver site traffic to userspace TUN. With DCO, OpenVPN
// installs more specific peer routes at a lower metric when the router connects.
// A private protocol/metric pair keeps our cleanup away from OpenVPN and host routes.
const routeProtocol = "186"
const routeMetric = "42760"

func syncRoutes(p networkpolicy.Policy) error {
	out, err := exec.Command("ip", "-j", "-4", "route", "show", "proto", routeProtocol).Output()
	if err != nil {
		return fmt.Errorf("Read managed routes: %w", err)
	}
	var existing []struct {
		Dst    string `json:"dst"`
		Dev    string `json:"dev"`
		Metric int    `json:"metric"`
	}
	if err := json.Unmarshal(out, &existing); err != nil {
		return err
	}
	wanted := map[string]bool{}
	if p.SiteToSite {
		for _, d := range p.Devices {
			for _, site := range d.Sites {
				wanted[site] = true
			}
		}
	}
	found := map[string]bool{}
	for _, route := range existing {
		if route.Dev != "tun0" || route.Metric != 42760 {
			continue
		}
		// iproute2 represents /32 destinations as bare addresses in JSON.
		prefix, err := netip.ParsePrefix(route.Dst)
		if address, parseErr := netip.ParseAddr(route.Dst); parseErr == nil && address.Is4() {
			prefix = netip.PrefixFrom(address, 32)
			err = nil
		}
		if err != nil || !prefix.Addr().Is4() {
			return fmt.Errorf("Invalid managed route")
		}
		if wanted[prefix.String()] {
			found[prefix.String()] = true
			continue
		}
		if err := command("ip", "-4", "route", "del", prefix.String(), "dev", "tun0", "proto", routeProtocol, "metric", routeMetric); err != nil {
			return err
		}
	}
	for site := range wanted {
		if !found[site] {
			if err := command("ip", "-4", "route", "add", site, "dev", "tun0", "proto", routeProtocol, "metric", routeMetric); err != nil {
				return err
			}
		}
	}
	return nil
}
func update(path, revision, egress string) error {
	next, data, err := load(path)
	if err != nil {
		return err
	}
	rev, err := strconv.ParseInt(revision, 10, 64)
	if err != nil || next.Revision != rev {
		return fmt.Errorf("Network and VPN settings revisions do not match")
	}
	previous, _, err := load(activePolicy)
	if err != nil {
		return err
	}
	if previous.Revision != rev || previous.Network != next.Network {
		return fmt.Errorf("Global settings require an OpenVPN restart")
	}
	if err := validateRuntime(next, egress); err != nil {
		return err
	}
	for _, cn := range changedPeers(previous, next) {
		// Management explicitly permits only desk's UID. Drop credentials in a child
		// process, keeping the privileged firewall/route supervisor out of the socket.
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		child := exec.CommandContext(ctx, executable, "disconnect", cn)
		child.Env = []string{}
		child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 10001, Gid: 10001}}
		out, err := child.CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("Reconnect changed VPN peer: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if err := apply(next, egress); err != nil {
		if rollback := apply(previous, egress); rollback != nil {
			return fmt.Errorf("%w; firewall rollback: %v", err, rollback)
		}
		return err
	}
	if err := syncRoutes(next); err != nil {
		firewallErr := apply(previous, egress)
		routesErr := syncRoutes(previous)
		return fmt.Errorf("%w; rollback firewall=%v routes=%v", err, firewallErr, routesErr)
	}
	// Publish only a complete applied snapshot. New handshakes wait while the
	// active and desired policies differ, including during a failed update.
	temporary, err := os.CreateTemp(filepath.Dir(activePolicy), ".network-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chown(10001, 10001); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), activePolicy)
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("Usage: vpn-network apply|update|routes|learn|connect")
	}
	switch args[0] {
	case "apply":
		if len(args) != 4 {
			return fmt.Errorf("Usage: vpn-network apply POLICY REVISION EGRESS")
		}
		p, _, err := load(args[1])
		if err != nil {
			return err
		}
		revision, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil || revision != p.Revision {
			return fmt.Errorf("Network and VPN settings revisions do not match")
		}
		if err := apply(p, args[3]); err != nil {
			return err
		}
		fmt.Print("script-security 2\nlearn-address /usr/local/bin/desk-learn-address\nclient-connect /usr/local/bin/desk-client-connect\n")
		return nil
	case "disconnect":
		if len(args) != 2 || !management.ValidCN(args[1]) {
			return fmt.Errorf("Invalid peer to disconnect")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		mgmt := management.Client{Socket: "/run/tunnelslate/management.sock"}
		return mgmt.Disconnect(ctx, args[1])
	case "update":
		if len(args) != 4 {
			return fmt.Errorf("Usage: vpn-network update POLICY REVISION EGRESS")
		}
		return update(args[1], args[2], args[3])
	case "routes":
		if len(args) != 1 {
			return fmt.Errorf("Usage: vpn-network routes")
		}
		p, _, err := load(activePolicy)
		if err != nil {
			return err
		}
		return syncRoutes(p)
	case "learn":
		if len(args) > 1 && args[1] == "delete" {
			return nil
		}
		if len(args) != 4 || (args[1] != "add" && args[1] != "update") {
			return fmt.Errorf("Invalid learn-address arguments")
		}
		p, _, err := load(activePolicy)
		if err != nil {
			return err
		}
		if !p.Learn(args[2], args[3], os.Getenv("ifconfig_pool_remote_ip")) {
			return fmt.Errorf("Source address is not assigned to this VPN peer")
		}
		return nil
	case "connect":
		p, _, err := load(activePolicy)
		if err != nil {
			return err
		}
		desired, _, err := load(desiredPolicy)
		if err != nil || !peerUnchanged(p, desired, os.Getenv("common_name")) {
			return fmt.Errorf("Network policy update pending; reconnect shortly")
		}
		assigned := os.Getenv("ifconfig_pool_remote_ip")
		if !p.Learn(assigned, os.Getenv("common_name"), assigned) {
			return fmt.Errorf("VPN address does not match the applied network policy")
		}
		return nil
	}
	return fmt.Errorf("Unknown vpn-network command")
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
