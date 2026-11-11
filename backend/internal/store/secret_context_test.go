package store

import (
	"context"
	"encoding/base64"
	"testing"
)

func TestSecretsPreserveOwnerAndPurposeBinding(t *testing.T) {
	ctx := context.Background()
	s := recoveryStore(t)
	const value = "private-test-secret"
	for _, tc := range []struct {
		name, purpose, keyPath string
		seal                   func() (string, error)
		open, wrongOwner       func(string) (string, error)
	}{
		{"totp", "totp/1", s.TOTPKeyPath(), func() (string, error) { return s.SealTOTPSecret(ctx, 1, value) }, func(v string) (string, error) { return s.OpenTOTPSecret(1, v) }, func(v string) (string, error) { return s.OpenTOTPSecret(2, v) }},
		{"vpn-auth", "vpn-auth/provider", s.VPNAuthKeyPath(), func() (string, error) { return s.SealVPNAuthSecret(ctx, "provider", value) }, func(v string) (string, error) { return s.OpenVPNAuthSecret("provider", v) }, func(v string) (string, error) { return s.OpenVPNAuthSecret("other-provider", v) }},
		{"metrics", "metrics/server", s.MetricsKeyPath(), func() (string, error) { return s.SealMetricsSecret(ctx, "server", value) }, func(v string) (string, error) { return s.OpenMetricsSecret("server", v) }, func(v string) (string, error) { return s.OpenMetricsSecret("other-server", v) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current, err := tc.seal()
			if err != nil {
				t.Fatal(err)
			}
			key, err := readTOTPKey(tc.keyPath)
			if err != nil {
				t.Fatal(err)
			}
			aead, err := totpCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := tc.open(current); err != nil || got != value {
				t.Fatal("secret round trip failed", err)
			}
			if _, err := tc.wrongOwner(current); err == nil {
				t.Fatal("secret bypassed owner binding")
			}
			tampered, err := base64.RawStdEncoding.DecodeString(current)
			if err != nil {
				t.Fatal(err)
			}
			tampered[len(tampered)-1] ^= 1
			if _, err := tc.open(base64.RawStdEncoding.EncodeToString(tampered)); err == nil {
				t.Fatal("tampered ciphertext accepted")
			}
			data, err := base64.RawStdEncoding.DecodeString(current)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], []byte("tunnelslate/"+tc.purpose)); err != nil || string(got) != value {
				t.Fatal("secret uses incorrect context", err)
			}
			if _, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], secretContext("another-purpose")); err == nil {
				t.Fatal("secret bypassed purpose binding")
			}
		})
	}
}
