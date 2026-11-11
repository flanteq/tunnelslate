package vpnauth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tunnelslate/internal/store"
	"tunnelslate/internal/vpnauthwire"
)

func fixture(t *testing.T) *Service {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "desk.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.DB.Close() })
	for _, query := range []string{
		`INSERT INTO clients(id,name,created_at) VALUES('client','Alice',1)`,
		`INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES('device','client','Laptop','desk-11111111111111111111111111111111',1)`,
		`INSERT INTO operations(id,kind,state,step,created_at,updated_at) VALUES('issue','issue','succeeded','complete',1,1)`,
		`INSERT INTO certificates(serial,device_id,status,not_before,not_after,common_name,operation_id) VALUES('ABCDEF','device','valid',1,4102444800,'desk-11111111111111111111111111111111','issue')`,
	} {
		if _, err = db.DB.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	return &Service{Store: db, ControlDir: t.TempDir()}
}
func radiusProvider() Provider {
	return Provider{Name: "Company RADIUS", Kind: "radius", Enabled: true, Secret: "a-test-shared-secret", Config: ProviderConfig{Address: "127.0.0.1:1812", NASIdentifier: "desk"}}
}
func policyEntry(t *testing.T, s *Service) (vpnauthwire.Entry, bool) {
	t.Helper()
	p, err := vpnauthwire.ReadPolicy(filepath.Join(s.ControlDir, vpnauthwire.PolicyName))
	if err != nil {
		t.Fatal(err)
	}
	e, ok := p.Entries["desk-11111111111111111111111111111111"]
	return e, ok
}
func TestClientPoliciesAndEncryptedSecrets(t *testing.T) {
	ctx := context.Background()
	s := fixture(t)
	if err := s.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	e, ok := policyEntry(t, s)
	if !ok || e.External {
		t.Fatal("default must be certificate only")
	}
	p, err := s.SaveProvider(ctx, radiusProvider(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if p.Secret != "" || !p.HasSecret {
		t.Fatal("secret returned")
	}
	var encrypted string
	if err = s.Store.DB.QueryRow("SELECT encrypted_secret FROM vpn_auth_providers").Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encrypted, "test-shared") {
		t.Fatal("plaintext secret")
	}
	info, err := os.Stat(s.Store.VPNAuthKeyPath())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("key permissions", err)
	}
	opened, err := s.Store.OpenVPNAuthSecret(p.ID, encrypted)
	if err != nil || opened != radiusProvider().Secret {
		t.Fatal(err)
	}
	if _, err = s.Store.OpenVPNAuthSecret("other", encrypted); err == nil {
		t.Fatal("ciphertext not bound to provider")
	}
	p.Name = "Renamed"
	p, err = s.SaveProvider(ctx, p, "admin")
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.SaveBinding(ctx, "client", Binding{Mode: "external", ProviderID: p.ID, Username: "alice"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !v.DisconnectPending {
		t.Fatal("policy change did not queue existing sessions")
	}
	if _, ok = policyEntry(t, s); ok {
		t.Fatal("pending disconnect allowed")
	}
	if _, err = s.Store.DB.Exec("DELETE FROM vpn_auth_disconnects"); err != nil {
		t.Fatal(err)
	}
	if err = s.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	e, ok = policyEntry(t, s)
	if !ok || !e.External {
		t.Fatal("external policy not published")
	}
	required, err := RequiresPassword(ctx, s.Store.DB, "device")
	if err != nil || !required {
		t.Fatal("device must use client authentication", required, err)
	}

	if err = s.DeleteProvider(ctx, p.ID, p.Revision, "admin"); err == nil {
		t.Fatal("deleted an assigned provider")
	}
	if _, err = s.SaveBinding(ctx, "client", Binding{Mode: "certificate", Revision: 0}, "admin"); err == nil {
		t.Fatal("stale update accepted")
	}
	v, err = s.SaveBinding(ctx, "client", Binding{Mode: "certificate", Revision: v.Binding.Revision}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteProvider(ctx, p.ID, p.Revision, "admin"); err != nil {
		t.Fatal(err)
	}
}
func TestExternalNeverFallsBackOrAcceptsAnotherIdentity(t *testing.T) {
	ctx := context.Background()
	s := fixture(t)
	p, err := s.SaveProvider(ctx, radiusProvider(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveBinding(ctx, "client", Binding{Mode: "external", ProviderID: p.ID, Username: "alice"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Store.DB.Exec("DELETE FROM vpn_auth_disconnects"); err != nil {
		t.Fatal(err)
	}
	r := vpnauthwire.Request{CommonName: "desk-11111111111111111111111111111111", Serial: "AB:CD:EF", IP: "192.0.2.1"}
	for _, user := range []string{"", "other-user"} {
		r.Username = user
		r.Password = "password"
		if s.Authenticate(ctx, r) {
			t.Fatal("missing/wrong identity accepted")
		}
	}
	var count int
	if err = s.Store.DB.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action='vpn.auth.reject' AND severity='WARNING'").Scan(&count); err != nil || count != 2 {
		t.Fatal(count, err)
	}
	r.Serial = "111"
	if s.Authenticate(ctx, r) {
		t.Fatal("wrong certificate serial accepted")
	}
	p.Enabled = false
	if _, err = s.SaveProvider(ctx, p, "admin"); err != nil {
		t.Fatal(err)
	}
	r.Username = "alice"
	r.Serial = "ABCDEF"
	if s.Authenticate(ctx, r) {
		t.Fatal("disabled provider accepted")
	}
}
func TestProviderValidationAndKeyLoss(t *testing.T) {
	ctx := context.Background()
	s := fixture(t)
	p := radiusProvider()
	p.Secret = "short"
	if _, err := s.SaveProvider(ctx, p, "admin"); err == nil {
		t.Fatal("weak RADIUS secret accepted")
	}
	p = radiusProvider()
	created, err := s.SaveProvider(ctx, p, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(s.Store.VPNAuthKeyPath()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveProvider(ctx, Provider{Name: "new", Kind: "radius", Enabled: true, Secret: p.Secret, Config: p.Config}, "admin"); err == nil {
		t.Fatal("lost key silently replaced")
	}
	var output []Provider
	output, err = s.Providers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(output)
	if strings.Contains(string(encoded), p.Secret) {
		t.Fatal("list leaked secret")
	}
	if output[0].ID != created.ID {
		t.Fatal(output)
	}
	ldap := Provider{Name: "LDAP", Kind: "ldap", Config: ProviderConfig{Address: "ldap://directory.example.com:389", BindDN: "cn=reader,dc=example,dc=com", BaseDN: "dc=example,dc=com", UserFilter: "(uid={username})"}}
	if err = validateProvider(&ldap); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"http://directory.example.com", "ldaps://user:pass@directory.example.com", "ldaps://directory.example.com/dc=example"} {
		ldap.Config.Address = address
		if err = validateProvider(&ldap); err == nil {
			t.Fatal("bad LDAP URL accepted", address)
		}
	}
}
func TestAttemptBudgetIsSeparateFromPanelAndBounded(t *testing.T) {
	s := fixture(t)
	for i := 0; i < 5; i++ {
		if !s.allowExternal("192.0.2.1", "device") {
			t.Fatal(i)
		}
		s.recordFailure("192.0.2.1", "device")
	}
	if s.allowExternal("192.0.2.1", "another") || s.allowExternal("192.0.2.2", "device") {
		t.Fatal("IP or device limit missing")
	}
	for key, b := range s.limits {
		b.Until = time.Now().Add(-time.Second)
		s.limits[key] = b
	}
	if !s.allowExternal("192.0.2.1", "device") {
		t.Fatal("expired limit retained")
	}
}

func TestClientPolicyDisconnectsAllDevices(t *testing.T) {
	ctx := context.Background()
	s := fixture(t)
	p, err := s.SaveProvider(ctx, radiusProvider(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.SaveBinding(ctx, "client", Binding{Mode: "external", ProviderID: p.ID, Username: "alice"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	required, err := RequiresPassword(ctx, s.Store.DB, "device")
	if err != nil || !required {
		t.Fatal("device did not inherit client authentication", err)
	}
	if _, err = s.Store.DB.Exec("DELETE FROM vpn_auth_disconnects"); err != nil {
		t.Fatal(err)
	}
	if err = s.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	e, ok := policyEntry(t, s)
	if !ok || !e.External {
		t.Fatal("local policy did not use client authentication", e)
	}
	if s.Authenticate(ctx, vpnauthwire.Request{CommonName: "desk-11111111111111111111111111111111", Serial: "ABCDEF", IP: "192.0.2.1", Username: "other-user", Password: "password"}) {
		t.Fatal("client policy allowed a different username")
	}
	if _, err = s.SaveBinding(ctx, "client", Binding{Mode: "external", ProviderID: p.ID, Username: "bob", Revision: v.Binding.Revision}, "admin"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.Store.DB.QueryRow("SELECT COUNT(*) FROM vpn_auth_disconnects").Scan(&count); err != nil || count != 1 {
		t.Fatal("client policy did not disconnect device", count, err)
	}
	if _, ok = policyEntry(t, s); ok {
		t.Fatal("policy published before disconnection")
	}
	if _, err = s.Store.DB.Exec("DELETE FROM vpn_auth_disconnects"); err != nil {
		t.Fatal(err)
	}
	if err = s.Publish(ctx); err != nil {
		t.Fatal(err)
	}
	e, ok = policyEntry(t, s)
	if !ok || !e.External {
		t.Fatal("client authentication lost after reconfiguration", e)
	}
}
