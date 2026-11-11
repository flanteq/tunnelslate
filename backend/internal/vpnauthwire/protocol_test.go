package vpnauthwire

import (
	"testing"
	"time"
)

func TestPolicyRequiresExactUnexpiredCertificate(t *testing.T) {
	p := Policy{Entries: map[string]Entry{"device": {Serial: "00ABCDEF", NotAfter: time.Now().Add(time.Hour).Unix()}}}
	r := Request{CommonName: "device", Serial: "AB:CD:EF"}
	if _, ok := p.Lookup(r); !ok {
		t.Fatal("same serial encoding rejected")
	}
	for _, serial := range []string{"", "0", "-ABCDEF", "other", "AABBCC"} {
		r.Serial = serial
		if _, ok := p.Lookup(r); ok {
			t.Fatal("invalid serial allowed", serial)
		}
	}
	r.Serial = "ABCDEF"
	r.CommonName = "other"
	if _, ok := p.Lookup(r); ok {
		t.Fatal("unknown device allowed")
	}
	r.CommonName = "device"
	p.Entries["device"] = Entry{Serial: "ABCDEF", NotAfter: time.Now().Add(-time.Second).Unix()}
	if _, ok := p.Lookup(r); ok {
		t.Fatal("expired certificate allowed")
	}
}
