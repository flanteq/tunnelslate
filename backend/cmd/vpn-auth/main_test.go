package main

import (
	"strings"
	"testing"

	"tunnelslate/internal/vpnauthwire"
)

func TestAuthenticationReceiptCannotOutliveOrCrossPolicies(t *testing.T) {
	version := vpnauthwire.Version("device", "ABCD", "provider", "alice", 1, 1)
	entry := vpnauthwire.Entry{External: true, Version: version}
	r := receipt{version, 1000}
	if !receiptMatches(entry, r, 1001) {
		t.Fatal("fresh receipt rejected")
	}
	for _, test := range []struct {
		entry vpnauthwire.Entry
		r     receipt
		now   int64
	}{
		{entry, r, 1061}, {entry, r, 999},
		{vpnauthwire.Entry{Version: vpnauthwire.Version("device", "ABCD", "provider", "alice", 2, 1)}, r, 1001},
		{vpnauthwire.Entry{Version: vpnauthwire.Version("device", "ABCD", "provider", "bob", 1, 2)}, r, 1001},
		{vpnauthwire.Entry{Version: vpnauthwire.Version("other-device", "ABCD", "provider", "alice", 1, 1)}, r, 1001},
		{vpnauthwire.Entry{}, receipt{}, 1000},
	} {
		if receiptMatches(test.entry, test.r, test.now) {
			t.Fatal("stale or mismatched receipt accepted", test)
		}
	}
}
func TestTemporaryPathsAndReceiptsAreBoundToPeer(t *testing.T) {
	a := receiptPath("cn", "192.0.2.1", "1000")
	if a == "" || !validTemporary(a) || strings.Contains(a, "192.0.2") {
		t.Fatal(a)
	}
	if a == receiptPath("cn", "192.0.2.1", "1001") || a == receiptPath("other", "192.0.2.1", "1000") {
		t.Fatal("receipt shared across sessions")
	}
	for _, path := range []string{"/etc/passwd", "/run/openvpn/auth/../secret", "/run/openvpn/auth"} {
		if validTemporary(path) {
			t.Fatal("unsafe temporary path", path)
		}
	}
	for _, ip := range []string{"", "not-an-ip"} {
		if receiptPath("cn", ip, "1000") != "" {
			t.Fatal("invalid peer allowed")
		}
	}
}
