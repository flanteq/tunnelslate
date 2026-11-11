package main

import (
	"reflect"
	"sort"
	"testing"
	"tunnelslate/internal/networkpolicy"
)

func TestChangedPeersReconnectOnlyChangedAddressOwners(t *testing.T) {
	original := networkpolicy.Policy{SiteToSite: true, Devices: []networkpolicy.Device{
		{ID: "router", CNs: []string{"router"}, IP: "10.8.0.128", Sites: []string{"192.168.80.0/24"}, Access: "all", DNS: []string{"192.0.2.53"}},
		{ID: "laptop", CNs: []string{"laptop"}, IP: "10.8.0.129"},
	}}
	for _, test := range []struct {
		name   string
		change func(*networkpolicy.Policy)
		want   []string
	}{
		{"ACL", func(p *networkpolicy.Policy) {
			p.Devices[0].Access = "restricted"
			p.Devices[0].Allowed = []string{"198.51.100.0/24"}
		}, []string{}},
		{"DNS", func(p *networkpolicy.Policy) { p.Devices[0].DNS = []string{"192.0.2.54"} }, []string{}},
		{"IP", func(p *networkpolicy.Policy) { p.Devices[0].IP = "10.8.0.130" }, []string{"router"}},
		{"LAN", func(p *networkpolicy.Policy) { p.Devices[0].Sites = []string{"192.168.81.0/24"} }, []string{"router"}},
		{"revocation", func(p *networkpolicy.Policy) { p.Devices[0].CNs = nil }, []string{"router"}},
		{"new static reservation", func(p *networkpolicy.Policy) {
			p.Devices = append(p.Devices, networkpolicy.Device{CNs: []string{"phone"}, IP: "10.8.0.131"})
		}, []string{"phone"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			next := original
			next.Devices = append([]networkpolicy.Device{}, original.Devices...)
			test.change(&next)
			got := changedPeers(original, next)
			sort.Strings(got)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestPendingPolicyOnlyBlocksAffectedHandshakes(t *testing.T) {
	original := networkpolicy.Policy{Revision: 1, Network: "10.8.0.0/24", Devices: []networkpolicy.Device{{ID: "router", CNs: []string{"router"}, IP: "10.8.0.128"}}}
	next := original
	next.Devices = append([]networkpolicy.Device{}, original.Devices...)
	next.Devices[0].Access = "restricted"
	if peerUnchanged(original, next, "router") {
		t.Fatal("changed peer bypassed pending rules")
	}
	if !peerUnchanged(original, next, "phone") {
		t.Fatal("unrelated dynamic peer rejected")
	}
	next.Revision = 2
	if peerUnchanged(original, next, "phone") {
		t.Fatal("global revision mismatch allowed")
	}
}
