// Package vpnauthwire is shared by the unprivileged VPN helper and the panel.
// It contains no directory credentials or database dependencies.
package vpnauthwire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"time"
)

const SocketName = "vpn-auth.sock"
const PolicyName = "vpn-auth.json"
const MaxRequest = 8192

const DefaultRADIUSTimeoutSeconds = 90
const MaxRADIUSTimeoutSeconds = 300
const AuthWorkTimeout = (MaxRADIUSTimeoutSeconds + 10) * time.Second
const AuthSocketTimeout = AuthWorkTimeout + 5*time.Second
const HandshakeWindowSeconds = MaxRADIUSTimeoutSeconds + 30

type Request struct {
	CommonName string `json:"common_name"`
	Serial     string `json:"serial"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	IP         string `json:"ip"`
}
type Response struct {
	Allowed bool   `json:"allowed"`
	Version string `json:"version,omitempty"`
}
type Entry struct {
	Serial   string `json:"serial"`
	NotAfter int64  `json:"not_after"`
	External bool   `json:"external"`
	Version  string `json:"version"`
}
type Policy struct {
	Entries map[string]Entry `json:"entries"`
}

func Serial(value string) string {
	value = strings.ReplaceAll(value, ":", "")
	n, ok := new(big.Int).SetString(value, 16)
	if !ok || n.Sign() <= 0 {
		return ""
	}
	return strings.ToUpper(n.Text(16))
}
func ReadPolicy(path string) (Policy, error) {
	var p Policy
	b, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if len(b) > 16<<20 {
		return p, errors.New("VPN authentication policy too large")
	}
	err = json.Unmarshal(b, &p)
	return p, err
}
func (p Policy) Lookup(r Request) (Entry, bool) {
	e, ok := p.Entries[r.CommonName]
	return e, ok && e.NotAfter > time.Now().Unix() && Serial(r.Serial) != "" && Serial(r.Serial) == Serial(e.Serial)
}

// Version binds an authentication result to the exact effective policy.
func Version(device, serial, provider, username string, providerRevision, bindingRevision int64) string {
	data, _ := json.Marshal([]any{device, Serial(serial), provider, username, providerRevision, bindingRevision})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
