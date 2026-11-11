package networkpolicy

import (
	"strings"
	"testing"
)

func fixture() Policy {
	return Policy{Revision: 1, Network: "10.8.0.0/24", SiteToSite: true, Devices: []Device{
		{ID: "a", IP: "10.8.0.128", CNs: []string{"peer-a"}, Sites: []string{"192.168.80.42/24"}, Access: "restricted", Allowed: []string{"192.168.81.0/24"}, DNS: []string{"192.0.2.53"}},
		{ID: "b", IP: "10.8.0.129", CNs: []string{"peer-b"}, Sites: []string{"192.168.81.0/24"}},
	}}
}

func TestRejectAmbiguousSitesAndDirectiveInjection(t *testing.T) {
	for _, change := range []func(*Policy){
		func(p *Policy) { p.Devices[1].Sites = []string{"192.168.80.128/25"} },
		func(p *Policy) { p.Devices[0].Sites = []string{"10.8.0.0/25"} },
		func(p *Policy) { p.Devices[0].Sites = []string{"0.0.0.0/0"} },
		func(p *Policy) { p.Devices[0].Sites = []string{"192.168.80.0/24\nscript-security 2"} },
		func(p *Policy) { p.Devices[0].Sites = []string{"::/64"} },
		func(p *Policy) { p.Devices[0].IP = "" },
		func(p *Policy) { p.Devices[0].Allowed = []string{"192.0.2.0/24;id"} },
		func(p *Policy) { p.Devices[1].IP = p.Devices[0].IP },
		func(p *Policy) { p.Devices[1].CNs = p.Devices[0].CNs },
	} {
		p := fixture()
		change(&p)
		if p.Validate() == nil {
			t.Fatalf("invalid policy accepted: %+v", p)
		}
	}
}

func TestSourceOwnershipIncludesOfflinePeers(t *testing.T) {
	p := fixture()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		address, cn, assigned string
		allow                 bool
	}{
		{"10.8.0.128", "peer-a", "10.8.0.128", true},
		{"192.168.80.20", "peer-a", "10.8.0.128", true},
		{"192.168.80.0/24", "peer-a", "10.8.0.128", true},
		{"192.168.81.20", "peer-a", "10.8.0.128", false},
		{"10.8.0.129", "peer-a", "10.8.0.128", false},
		{"10.8.0.3", "dynamic", "10.8.0.2", false},
		{"10.8.0.2", "dynamic", "10.8.0.2", true},
		{"10.8.0.128", "dynamic", "10.8.0.128", false},
	} {
		if got := p.Learn(v.address, v.cn, v.assigned); got != v.allow {
			t.Fatalf("%+v: %v", v, got)
		}
	}
	p.SiteToSite = false
	if p.Learn("192.168.80.20", "peer-a", "10.8.0.128") {
		t.Fatal("disabled site source allowed")
	}
}

func TestRoutesAndFirewallDoNotPermitEstablishedTrafficToBypassPolicy(t *testing.T) {
	p := fixture()
	p.Isolate = true
	p.SiteNAT = true
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	rules := p.Rules("eth0")
	for _, want := range []string{"-i tun+ -o tun+ -j DROP", "-d 192.168.80.0/24 ! -o tun+ -j DROP", "--dport 53", "--sport 53 -m conntrack --ctstate ESTABLISHED", "-A DESK_NET_D0 -s 192.168.81.0/24 -j RETURN", "-A DESK_NET_S0 -j DROP", "-s 192.168.80.0/24 -o eth0 -j MASQUERADE"} {
		if !strings.Contains(rules, want) {
			t.Fatal("missing", want, rules)
		}
	}
	if strings.Contains(rules, "--ctstate ESTABLISHED,RELATED") {
		t.Fatal("blanket established exemption")
	}
	p.SiteToSite = false
	if strings.Contains(p.Rules("eth0"), "-o eth0 -j MASQUERADE") {
		t.Fatal("disabled sites remain routed or NATed")
	}
}
