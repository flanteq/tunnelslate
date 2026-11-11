package vpnsettings

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type DCOStatus struct {
	State         string `json:"state"`
	Reason        string `json:"reason"`
	KernelRelease string `json:"kernel_release,omitempty"`
	ModuleLoaded  *bool  `json:"module_loaded,omitempty"`
}

// Probe data comes from the VPN container and is only used for the applied revision.
func (s *Service) DCOStatus(ctx context.Context, running bool, enabled, supported *bool, applied int64) DCOStatus {
	result := DCOStatus{State: "unknown", Reason: "server_unavailable"}
	if !running {
		return result
	}
	result.Reason = "status_unavailable"
	if probe, err := os.Open(filepath.Join(s.ControlDir, "dco-host-status")); err == nil {
		data, err := io.ReadAll(io.LimitReader(probe, 4097))
		probe.Close()
		if err == nil && len(data) <= 4096 {
			values := map[string]string{}
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if key, value, ok := strings.Cut(line, "="); ok {
					values[key] = value
				}
			}
			revision, err := strconv.ParseInt(values["revision"], 10, 64)
			if err == nil && revision > 0 && revision == applied {
				result.KernelRelease = values["kernel_release"]
				if value := values["module_loaded"]; value == "true" || value == "false" {
					loaded := value == "true"
					result.ModuleLoaded = &loaded
				}
			}
		}
	}
	if enabled == nil {
		return result
	}
	if *enabled {
		result.State, result.Reason = "active", "active"
		return result
	}
	settings, err := s.Get(ctx)
	if err == nil && settings.Revision == applied && settings.DCO == "off" {
		result.State, result.Reason = "disabled", "disabled_by_settings"
		return result
	}
	result.State, result.Reason = "unavailable", "not_used"
	if supported != nil && !*supported {
		result.Reason = "build_unsupported"
	} else if result.ModuleLoaded != nil && !*result.ModuleLoaded {
		result.Reason = "kernel_module_missing"
	}
	return result
}
