package vpnsettings

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"tunnelslate/internal/config"
	"tunnelslate/internal/store"
)

func TestDCOStatusUsesActualDaemonStateAndMatchingProbe(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(root, "desk.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.DB.Close()
	s := &Service{Store: db, ControlDir: root}
	if err := s.Ensure(ctx, config.Config{PublicURL: "https://vpn.test"}); err != nil {
		t.Fatal(err)
	}
	yes, no := true, false
	probe := func(revision string, loaded string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, "dco-host-status"), []byte("revision="+revision+"\nkernel_release=test-kernel\nmodule_loaded="+loaded+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	probe("1", "false")
	for _, tc := range []struct {
		name           string
		running        bool
		enabled, built *bool
		revision       int64
		state, reason  string
	}{
		{"offline", false, &yes, &yes, 1, "unknown", "server_unavailable"},
		{"old status", true, nil, &yes, 1, "unknown", "status_unavailable"},
		{"active overrides probe", true, &yes, &yes, 1, "active", "active"},
		{"module absent", true, &no, &yes, 1, "unavailable", "kernel_module_missing"},
		{"not compiled", true, &no, &no, 1, "unavailable", "build_unsupported"},
		{"stale probe", true, &no, &yes, 2, "unavailable", "not_used"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := s.DCOStatus(ctx, tc.running, tc.enabled, tc.built, tc.revision)
			if got.State != tc.state || got.Reason != tc.reason {
				t.Fatalf("status=%+v", got)
			}
			if tc.revision == 2 && (got.KernelRelease != "" || got.ModuleLoaded != nil) {
				t.Fatal("stale probe reported current capabilities")
			}
		})
	}
	v, _ := s.Get(ctx)
	v.DCO = "off"
	v, err = s.Save(ctx, v, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.DCOStatus(ctx, true, &no, &yes, 1); got.State == "disabled" {
		t.Fatal("unapplied desired setting reported as active configuration")
	}
	probe("2", "true")
	if got := s.DCOStatus(ctx, true, &no, &yes, v.Revision); got.State != "disabled" || got.Reason != "disabled_by_settings" {
		t.Fatalf("status=%+v", got)
	}
}
