package vpnoptions

import (
	"strings"
	"testing"
)

func TestDomainsNormalizeAndRejectConfigInjection(t *testing.T) {
	domain := " Office.Example.COM. "
	search := []string{" Dev.Example.COM. ", "dev.example.com", "xn--e1afmkfd.xn--p1ai"}
	if err := Domains(&domain, &search); err != nil || domain != "office.example.com" || len(search) != 2 || search[0] != "dev.example.com" {
		t.Fatal(domain, search, err)
	}
	for _, invalid := range []string{".", "a..example", "-bad.example", "bad-.example", "bad_name", "пример.рф", "example.com\npush route", "a\";id", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "a"} {
		for _, primary := range []bool{true, false} {
			domain, search = "", nil
			if primary {
				domain = invalid
			} else {
				search = []string{invalid}
			}
			if Domains(&domain, &search) == nil {
				t.Fatalf("accepted %q", invalid)
			}
		}
	}
	domain, search = "", make([]string, 11)
	if Domains(&domain, &search) == nil {
		t.Fatal("accepted more than 10 domains")
	}
}

func TestLinkLimitsAndProfileDirectives(t *testing.T) {
	for _, v := range []Link{{TunMTU: 575}, {TunMTU: 1501}, {MSSMode: "invalid"}, {MSSMode: "custom", MSS: 535}, {MSSMode: "custom", MSS: 1461}, {TunMTU: 1400, MSSMode: "custom", MSS: 1361}} {
		if v.Validate() == nil {
			t.Fatalf("accepted %+v", v)
		}
	}
	v := Link{}
	if err := v.Validate(); err != nil || v.MSSMode != "default" || v.Directives("udp") != "" {
		t.Fatal(v, err)
	}
	v = Link{TunMTU: 1400, MSSMode: "custom", MSS: 1320}
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := v.Directives("udp"); got != "tun-mtu 1400\n# TCP MSS limited to 1320 bytes by the server\nmssfix 0\n" {
		t.Fatal(got)
	}
	if got := v.Directives("tcp"); got != "tun-mtu 1400\n" {
		t.Fatal(got)
	}
	v.MSSMode = "off"
	if err := v.Validate(); err != nil || v.MSS != 0 || v.Directives("udp") != "tun-mtu 1400\nmssfix 0\n" {
		t.Fatal(v, err)
	}
}
