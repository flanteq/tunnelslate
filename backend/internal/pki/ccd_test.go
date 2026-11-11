package pki

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"tunnelslate/internal/ccd"
	"tunnelslate/internal/management"
	"tunnelslate/internal/networkpolicy"
)

func enableCCD(t *testing.T, s *Service) {
	t.Helper()
	s.CCDDir = filepath.Join(t.TempDir(), "ccd")
	if _, err := s.Store.DB.Exec(`INSERT INTO vpn_settings(id,configuration,revision,updated_at) VALUES (1,'{"network":"10.8.0.0/24","dns":["192.0.2.53"],"routes":[]}',1,0)`); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkPoliciesAllocateStableAddressesAndRejectSiteOverlap(t *testing.T) {
	s, _ := serviceFixture(t)
	enableCCD(t, s)
	ctx := context.Background()
	for _, id := range []string{"router-a", "router-b"} {
		if _, err := s.Store.DB.Exec("INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES (?,'client',?,?,0)", id, id, id); err != nil {
			t.Fatal(err)
		}
	}
	value := ccd.Defaults()
	value.AccessMode = "restricted"
	value.AllowedNetworks = []string{"198.51.100.0/24"}
	value.SiteNetworks = []string{"192.168.80.42/24"}
	a, err := s.SaveDeviceCCD(ctx, "router-a", value, 1, "admin")
	if err != nil || a.Settings.StaticIP != "10.8.0.128" || a.Settings.SiteNetworks[0] != "192.168.80.0/24" {
		t.Fatal(a, err)
	}
	value.SiteNetworks = []string{"192.168.80.128/25"}
	if _, err := s.SaveDeviceCCD(ctx, "router-b", value, 1, "admin"); err == nil {
		t.Fatal("overlapping site assigned to another router")
	}
	var count int
	if err := s.Store.DB.QueryRow("SELECT count(*) FROM device_ccd WHERE device_id='router-b'").Scan(&count); err != nil || count != 0 {
		t.Fatal("failed assignment persisted", count, err)
	}
	value.SiteNetworks = []string{"192.168.81.0/24"}
	b, err := s.SaveDeviceCCD(ctx, "router-b", value, 1, "admin")
	if err != nil || b.Settings.StaticIP != "10.8.0.129" {
		t.Fatal(b, err)
	}
	if err := s.ValidateCCDNetwork(ctx, "10.9.0.0/24"); err == nil {
		t.Fatal("subnet change orphaned policy addresses")
	}
	restarted := &Service{Store: s.Store, PKIDir: s.PKIDir, RuntimeDir: s.RuntimeDir, CCDDir: s.CCDDir}
	if err := restarted.PublishCCD(ctx); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(s.RuntimeDir, "network.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy networkpolicy.Policy
	if err := json.Unmarshal(body, &policy); err != nil || len(policy.Devices) != 2 {
		t.Fatal(string(body), err)
	}
	// Revoked/offline router addresses and networks stay reserved and blocked.
	if !strings.Contains(policy.Rules("eth0"), "-s 10.8.0.128/32 -j DROP") {
		t.Fatal("offline device can still send traffic")
	}
}

func TestCCDChangedAddressHeldUntilOldConnectionEnds(t *testing.T) {
	s, m := serviceFixture(t)
	ctx := context.Background()
	op, err := s.Start(ctx, "admin", "ccd-retire-address1", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	enableCCD(t, s)
	v := ccd.Defaults()
	v.StaticIP = "10.8.0.200"
	view, err := s.SaveDeviceCCD(ctx, op.DeviceID, v, 1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, args, _ := s.operation(ctx, op.ID)
	m.mu.Lock()
	m.active[args.CN] = true
	m.addresses[args.CN] = "10.8.0.200"
	m.mu.Unlock()
	v = view.Settings
	v.StaticIP = "10.8.0.201"
	if _, err := s.SaveDeviceCCD(ctx, op.DeviceID, v, 1, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.DB.Exec("INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES ('other','client','Phone','device-other',0)"); err != nil {
		t.Fatal(err)
	}
	other := ccd.Defaults()
	other.StaticIP = "10.8.0.200"
	if _, err := s.SaveDeviceCCD(ctx, "other", other, 1, "admin"); err == nil {
		t.Fatal("old live address reused")
	}
	if _, err := s.Store.DB.Exec("UPDATE device_ccd_retired_ips SET release_after=0"); err != nil {
		t.Fatal(err)
	}
	if err := s.PublishCCD(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveDeviceCCD(ctx, "other", other, 1, "admin"); err == nil {
		t.Fatal("active address released after grace period")
	}
	m.mu.Lock()
	delete(m.active, args.CN)
	m.mu.Unlock()
	s.Management = &management.Client{Socket: filepath.Join(t.TempDir(), "offline.sock")}
	if err := s.PublishCCD(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveDeviceCCD(ctx, "other", other, 1, "admin"); err == nil {
		t.Fatal("address released without management confirmation")
	}
	s.Management = &management.Client{Socket: m.socket}
	if err := s.PublishCCD(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveDeviceCCD(ctx, "other", other, 1, "admin"); err != nil {
		t.Fatal("unused address not released", err)
	}
}

func TestCCDRotationRevocationAndDeletion(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	first, err := s.Start(ctx, "admin", "ccd-issue-first-001", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	enableCCD(t, s)
	v := ccd.Defaults()
	v.StaticIP = "10.8.0.200"
	v.DNSMode = "custom"
	v.DNS = []string{"203.0.113.53"}
	view, err := s.SaveDeviceCCD(ctx, first.DeviceID, v, 1, "admin")
	if err != nil || !view.Published {
		t.Fatal(view, err)
	}
	_, args, _ := s.operation(ctx, first.ID)
	oldPath := filepath.Join(s.CCDDir, args.CN)
	body, err := os.ReadFile(oldPath)
	if err != nil || !strings.Contains(string(body), "10.8.0.200") {
		t.Fatal(string(body), err)
	}
	if info, _ := os.Stat(oldPath); info.Mode().Perm() != 0600 {
		t.Fatal("CCD permissions")
	}
	rotated, err := s.Start(ctx, "admin", "ccd-rotate-first-01", "rotate", first.DeviceID, "")
	if err != nil || rotated.State != "succeeded" {
		t.Fatal(rotated, err)
	}
	_, args, _ = s.operation(ctx, rotated.ID)
	newPath := filepath.Join(s.CCDDir, args.CN)
	after, err := os.ReadFile(newPath)
	if err != nil || string(after) != string(body) {
		t.Fatal("rotation lost CCD", string(after), err)
	}
	if _, err := os.Stat(oldPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old CN CCD survived", err)
	}
	if _, err := s.Start(ctx, "admin", "ccd-revoke-first-01", "revoke", rotated.ResultSerial, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(newPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("revoked CCD survived", err)
	}
	second, err := s.Start(ctx, "admin", "ccd-issue-second-01", "issue", "client", "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveDeviceCCD(ctx, second.DeviceID, v, 1, "admin"); err == nil {
		t.Fatal("reserved revoked device address reused")
	}
	if _, err := s.Start(ctx, "admin", "ccd-delete-first-01", "delete", first.DeviceID, ""); err != nil {
		t.Fatal(err)
	}
	view, err = s.SaveDeviceCCD(ctx, second.DeviceID, v, 1, "admin")
	if err != nil || view.Settings.StaticIP != v.StaticIP {
		t.Fatal("deleted address not released", view, err)
	}
	if _, err := s.Start(ctx, "admin", "ccd-delete-client01", "delete_client", "client", ""); err != nil {
		t.Fatal(err)
	}
	var reserved int
	if err := s.Store.DB.QueryRow("SELECT count(*) FROM device_ccd WHERE static_ip!=''").Scan(&reserved); err != nil || reserved != 0 {
		t.Fatal("client deletion kept addresses", reserved, err)
	}
	entries, err := os.ReadDir(s.CCDDir)
	if err != nil || len(entries) != 0 {
		t.Fatal("client CCD files survived", entries, err)
	}
}

func TestCCDPublicationFailureRecoversWithoutLosingSettings(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	op, err := s.Start(ctx, "admin", "ccd-publish-fail-001", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	enableCCD(t, s)
	if err := os.WriteFile(s.CCDDir, []byte("blocked directory"), 0600); err != nil {
		t.Fatal(err)
	}
	v := ccd.Defaults()
	v.StaticIP = "10.8.0.200"
	if _, err := s.SaveDeviceCCD(ctx, op.DeviceID, v, 1, "admin"); err == nil {
		t.Fatal("publication falsely succeeded")
	}
	view, err := s.DeviceCCD(ctx, op.DeviceID)
	if err != nil || view.Published || view.Settings.Revision != 1 || view.PublicationError == "" {
		t.Fatal(view, err)
	}
	if err := os.Remove(s.CCDDir); err != nil {
		t.Fatal(err)
	}
	if err := s.PublishCCD(ctx); err != nil {
		t.Fatal(err)
	}
	view, err = s.DeviceCCD(ctx, op.DeviceID)
	if err != nil || !view.Published || view.PublicationError != "" {
		t.Fatal(view, err)
	}
	// Recreate missing files from the database after restart/restore.
	_, args, _ := s.operation(ctx, op.ID)
	if err := os.Remove(filepath.Join(s.CCDDir, args.CN)); err != nil {
		t.Fatal(err)
	}
	if err := s.PublishCCD(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.CCDDir, args.CN)); err != nil {
		t.Fatal(err)
	}
	view.Settings = ccd.Defaults()
	view.Settings.Revision = 1
	if _, err := s.SaveDeviceCCD(ctx, op.DeviceID, view.Settings, 1, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.CCDDir, args.CN)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reset kept CCD file", err)
	}
}

func TestCCDConcurrentAddressReservationAndStaleSave(t *testing.T) {
	s, _ := serviceFixture(t)
	enableCCD(t, s)
	for _, id := range []string{"a", "b"} {
		if _, err := s.Store.DB.Exec("INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES (?,'client',?,?,0)", id, id, "device-"+id); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, id := range []string{"a", "b"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			v := ccd.Defaults()
			v.StaticIP = "10.8.0.200"
			_, err := s.SaveDeviceCCD(context.Background(), id, v, 1, "admin")
			results <- err
		}(id)
	}
	wg.Wait()
	close(results)
	passed, failed := 0, 0
	for err := range results {
		if err == nil {
			passed++
		} else {
			var e *Error
			if !errors.As(err, &e) || e.Code != 409 {
				t.Fatal(err)
			}
			failed++
		}
	}
	if passed != 1 || failed != 1 {
		t.Fatal(passed, failed)
	}
	if err := s.ValidateCCDNetwork(context.Background(), "10.9.0.0/24"); err == nil {
		t.Fatal("network change orphaned static IP")
	}
	var device string
	if err := s.Store.DB.QueryRow("SELECT device_id FROM device_ccd WHERE static_ip!=''").Scan(&device); err != nil {
		t.Fatal(err)
	}
	v := ccd.Defaults()
	if _, err := s.SaveDeviceCCD(context.Background(), device, v, 1, "admin"); err == nil {
		t.Fatal("stale revision accepted")
	}
	if _, err := s.SaveDeviceCCD(context.Background(), "missing", v, 1, "admin"); err == nil {
		t.Fatal("missing device accepted")
	}
	var data string
	if err := s.Store.DB.QueryRow("SELECT configuration FROM device_ccd WHERE device_id=?", device).Scan(&data); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(data), &v); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveDeviceCCD(context.Background(), device, v, 2, "admin"); err == nil {
		t.Fatal("stale global settings accepted")
	}
}

func TestSiteRoutesPublishedForDevicesWithoutOwnCCD(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx := context.Background()
	first, err := s.Start(ctx, "admin", "site-default-peer1", "issue", "client", "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	enableCCD(t, s)
	if _, err = s.Store.DB.Exec(`UPDATE vpn_settings SET configuration='{"network":"10.8.0.0/24","dns":["192.0.2.53"],"site_to_site":true}' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Store.DB.Exec(`INSERT INTO devices(id,client_id,name,common_name,created_at) VALUES('router','client','Router','router',0)`); err != nil {
		t.Fatal(err)
	}
	value := ccd.Defaults()
	value.SiteNetworks = []string{"192.168.80.0/24"}
	view, err := s.SaveDeviceCCD(ctx, "router", value, 1, "admin")
	if err != nil {
		t.Fatal(err)
	}
	_, args, _ := s.operation(ctx, first.ID)
	body, err := os.ReadFile(filepath.Join(s.CCDDir, args.CN))
	if err != nil || !strings.Contains(string(body), `push "route 192.168.80.0 255.255.255.0"`) {
		t.Fatal(string(body), err)
	}
	view.Settings.SiteNetworks = nil
	if _, err = s.SaveDeviceCCD(ctx, "router", view.Settings, 1, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(s.CCDDir, args.CN)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("removed LAN left stale default CCD", err)
	}
}
