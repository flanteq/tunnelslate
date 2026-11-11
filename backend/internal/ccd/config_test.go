package ccd

import (
	"strings"
	"testing"
)

func TestAddressRangesAndValidation(t *testing.T) {
	for _, test := range []struct{ network, start, end, dynamicEnd string }{
		{"10.8.0.0/24", "10.8.0.128", "10.8.0.254", "10.8.0.127"},
		{"172.27.13.42/23", "172.27.13.0", "172.27.13.254", "172.27.12.255"},
		{"192.0.2.0/29", "192.0.2.4", "192.0.2.6", "192.0.2.3"},
	} {
		dynamic, fixed, err := Ranges(test.network)
		if err != nil || fixed.Start != test.start || fixed.End != test.end || dynamic.End != test.dynamicEnd {
			t.Fatalf("%s: %+v %+v %v", test.network, dynamic, fixed, err)
		}
		for _, ip := range []string{test.start, test.end} {
			v := Defaults()
			v.StaticIP = ip
			if err := Validate(&v, test.network); err != nil {
				t.Fatal(err)
			}
		}
		v := Defaults()
		v.StaticIP = dynamic.End
		if Validate(&v, test.network) == nil {
			t.Fatal("dynamic address accepted as static")
		}
	}
	for _, ip := range []string{"10.8.0.1", "10.8.0.255", "10.9.0.128", "::1", "10.8.0.128\npush \"redirect-gateway\""} {
		v := Defaults()
		v.StaticIP = ip
		if Validate(&v, "10.8.0.0/24") == nil {
			t.Fatalf("accepted %q", ip)
		}
	}
}

func TestRenderOverridesPreserveTunnelInfrastructure(t *testing.T) {
	g := Global{Network: "10.8.0.0/24", DNS: []string{"192.0.2.53"}, Routes: []string{"198.51.100.0/24"}, RedirectGateway: true}
	v := Defaults()
	b, err := Render(v, g)
	if err != nil || len(b) != 0 {
		t.Fatal("inherited config should not need a file", string(b), err)
	}
	v.StaticIP = "10.8.0.200"
	v.DNSMode = "custom"
	v.DNS = []string{"203.0.113.53"}
	v.TunnelMode = "split"
	b, err = Render(v, g)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{"ifconfig-push 10.8.0.200 255.255.255.0", `push-remove "dhcp-option DNS "`, `push-remove "route "`, `push "route 198.51.100.0 255.255.255.0"`, `push "route 203.0.113.53 255.255.255.255"`, `push-remove "redirect-gateway"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %s", want, text)
		}
	}
	if strings.Contains(text, "192.0.2.53") || strings.Contains(text, "push-reset") || strings.Contains(text, `push-remove "route"`) {
		t.Fatal("overrides removed infrastructure or kept old DNS route", text)
	}
	v.RoutesMode = "custom"
	v.Routes = []string{}
	v.DNSMode = "inherit"
	v.DNS = nil
	v.TunnelMode = "full"
	b, err = Render(v, g)
	if err != nil || strings.Contains(string(b), "198.51.100.0") || !strings.Contains(string(b), `push "route 192.0.2.53 255.255.255.255"`) || !strings.Contains(string(b), `push "redirect-gateway def1 bypass-dhcp"`) {
		t.Fatal(string(b), err)
	}
}

func TestRejectDirectiveInjectionAndMalformedOptions(t *testing.T) {
	for _, modify := range []func(*Settings){
		func(v *Settings) { v.DNSMode = "custom"; v.DNS = []string{"192.0.2.53\npush \"route 0.0.0.0\""} },
		func(v *Settings) { v.DNSMode = "custom"; v.DNS = []string{} },
		func(v *Settings) { v.RoutesMode = "custom"; v.Routes = []string{"192.0.2.0/24\nscript-security 2"} },
		func(v *Settings) { v.RoutesMode = "custom"; v.Routes = []string{"::/64"} },
		func(v *Settings) { v.RoutesMode = "custom"; v.Routes = []string{"0.0.0.0/0"} },
		func(v *Settings) { v.TunnelMode = "custom" },
	} {
		v := Defaults()
		modify(&v)
		if Validate(&v, "10.8.0.0/24") == nil {
			t.Fatalf("accepted %+v", v)
		}
	}
}

func TestDNSDomainsOverridesAreIndependentAndCanClearSharedDomains(t *testing.T) {
	g := Global{Network: "10.8.0.0/24", DNS: []string{"192.0.2.53"}, DNSDomain: "office.example.com", DNSSearch: []string{"dev.example.com"}}
	v := Defaults()
	v.DNSMode = "custom"
	v.DNS = []string{"203.0.113.53"}
	body, err := Render(v, g)
	if err != nil || strings.Contains(string(body), "DOMAIN") {
		t.Fatal("DNS server override changed inherited domains", string(body), err)
	}
	v.DNSMode = "inherit"
	v.DNSDomainsMode = "custom"
	body, err = Render(v, g)
	if err != nil || !strings.Contains(string(body), `push-remove "dhcp-option DOMAIN "`) || !strings.Contains(string(body), `push-remove "dhcp-option DOMAIN-SEARCH "`) || strings.Contains(string(body), `push-remove "dhcp-option DNS "`) {
		t.Fatal(string(body), err)
	}
	if !Customized(v) {
		t.Fatal("domain-only overrides must appear as custom CCD")
	}
	v.DNSDomain = "Contractor.EXAMPLE.com."
	v.DNSSearch = []string{"contractor.example.com", "dev.example.com"}
	body, err = Render(v, g)
	if err != nil || !strings.Contains(string(body), `push "dhcp-option DOMAIN contractor.example.com"`) || !strings.Contains(string(body), `push "dhcp-option DOMAIN-SEARCH dev.example.com"`) {
		t.Fatal(string(body), err)
	}
	v.DNSDomain = "example.com\nscript-security 2"
	if _, err = Render(v, g); err == nil {
		t.Fatal("domain injection accepted")
	}
	v.DNSDomainsMode = "inherit"
	if err = Validate(&v, g.Network); err != nil || v.DNSDomain != "" || len(v.DNSSearch) != 0 {
		t.Fatal(v, err)
	}
}

func TestSiteRoutesReachDefaultDevicesWithoutPushingTheirOwnLAN(t *testing.T) {
	g := Global{Network: "10.8.0.0/24", DNS: []string{"192.0.2.53"}, SiteToSite: true, SiteNetworks: []string{"192.168.80.0/24", "192.168.81.0/24"}}
	body, err := Render(Defaults(), g)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`push "route 192.168.80.0 255.255.255.0"`, `push "route 192.168.81.0 255.255.255.0"`, `push "route 192.0.2.53 255.255.255.255"`} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
	value := Defaults()
	value.StaticIP = "10.8.0.128"
	value.SiteNetworks = []string{"192.168.80.0/24"}
	body, err = Render(value, g)
	if err != nil || strings.Contains(string(body), `push "route 192.168.80.0 `) || !strings.Contains(string(body), `iroute 192.168.80.0 255.255.255.0`) {
		t.Fatal(string(body), err)
	}
	g.SiteToSite = false
	body, err = Render(Defaults(), g)
	if err != nil || len(body) != 0 {
		t.Fatal("disabled sites leave stale pushes", string(body), err)
	}
}

func TestManagedHeader(t *testing.T) {
	if !IsManaged(Header + "ifconfig-push 10.8.0.130 255.255.255.0\n") {
		t.Fatal("managed file not recognized")
	}
	for _, body := range []string{"# Manually managed\n", "# Managed by TunnelSlate CCD extra\n", "# Managed by TunnelSlate CCD", "ifconfig-push 10.8.0.130 255.255.255.0\n"} {
		if IsManaged(body) {
			t.Fatal("manual file incorrectly treated as managed", body)
		}
	}
}
