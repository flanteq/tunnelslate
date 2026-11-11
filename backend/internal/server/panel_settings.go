package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"tunnelslate/internal/metricsweb"
	"tunnelslate/internal/store"
)

func panelError(w http.ResponseWriter, status int, code string) {
	jsonResponse(w, status, map[string]any{"error": code, "code": code})
}
func (s *Server) panelView(ctx context.Context) (map[string]any, error) {
	p, err := s.store.PanelSettings(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"settings": p, "runtime": s.metrics.Status()}, nil
}
func (s *Server) getPanelSettings(w http.ResponseWriter, r *http.Request) {
	view, err := s.panelView(r.Context())
	if err != nil {
		internalError(w, "read panel settings", err)
		return
	}
	jsonResponse(w, 200, view)
}
func (s *Server) metricsConfig(ctx context.Context, p store.PanelSettings) (metricsweb.Prepared, error) {
	c := metricsweb.Config{Enabled: p.MetricsEnabled, MTLS: p.MetricsMTLS, Source: p.MetricsSource, Cert: p.ServerCert, CA: p.ClientCA, Directory: filepath.Join(filepath.Dir(s.cfg.DBPath), "certs", "metrics")}
	if c.Enabled && c.MTLS && c.Source == "pem" && p.EncryptedKey != "" {
		key, err := s.store.OpenMetricsSecret("server-key", p.EncryptedKey)
		if err != nil {
			return metricsweb.Prepared{}, errors.New("metrics.secret")
		}
		c.Key = key
	}
	return metricsweb.Prepare(c)
}
func decodePanel(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 384*1024))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		panelError(w, 400, "panel.invalid_request")
		return false
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		panelError(w, 400, "panel.invalid_request")
		return false
	}
	return true
}
func (s *Server) savePanelGeneral(w http.ResponseWriter, r *http.Request) {
	var input struct {
		InstanceName string `json:"instance_name"`
		Revision     int64  `json:"revision"`
	}
	if !decodePanel(w, r, &input) {
		return
	}
	input.InstanceName = strings.TrimSpace(input.InstanceName)
	if !utf8.ValidString(input.InstanceName) || utf8.RuneCountInString(input.InstanceName) > 64 || strings.IndexFunc(input.InstanceName, unicode.IsControl) >= 0 {
		panelError(w, 400, "panel.instance_name")
		return
	}
	s.panelMu.Lock()
	defer s.panelMu.Unlock()
	p, err := s.store.PanelSettings(r.Context())
	if err != nil {
		internalError(w, "read panel settings", err)
		return
	}
	if p.Revision != input.Revision {
		panelError(w, 409, "panel.revision")
		return
	}
	p.InstanceName = input.InstanceName
	if err = s.store.SavePanelSettings(r.Context(), p, current(r).Username, "panel.settings.update"); err != nil {
		s.panelSaveError(w, err)
		return
	}
	s.invalidate("dashboard", "panel-settings", "audit")
	s.getPanelSettings(w, r)
}
func (s *Server) panelSaveError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrPanelRevision) {
		panelError(w, 409, "panel.revision")
	} else {
		internalError(w, "save panel settings", err)
	}
}
func (s *Server) saveMetricsSettings(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Enabled  bool   `json:"enabled"`
		MTLS     bool   `json:"mtls"`
		Source   string `json:"source"`
		Cert     string `json:"server_cert_pem"`
		CA       string `json:"client_ca_pem"`
		Key      string `json:"private_key_pem"`
		Revision int64  `json:"revision"`
	}
	if !decodePanel(w, r, &input) {
		return
	}
	if len(input.Cert) > 128*1024 || len(input.CA) > 128*1024 || len(input.Key) > 128*1024 {
		panelError(w, 400, "panel.invalid_request")
		return
	}
	s.panelMu.Lock()
	defer s.panelMu.Unlock()
	old, err := s.store.PanelSettings(r.Context())
	if err != nil {
		internalError(w, "read panel settings", err)
		return
	}
	if old.Revision != input.Revision {
		panelError(w, 409, "panel.revision")
		return
	}
	p := old
	p.MetricsEnabled = input.Enabled
	p.MetricsMTLS = input.MTLS
	p.MetricsSource = input.Source
	p.ServerCert = strings.TrimSpace(input.Cert)
	p.ClientCA = strings.TrimSpace(input.CA)
	if strings.TrimSpace(input.Key) != "" {
		p.EncryptedKey, err = s.store.SealMetricsSecret(r.Context(), "server-key", input.Key)
		if err != nil {
			panelError(w, 400, "metrics.secret")
			return
		}
	}
	prepared, err := s.metricsConfig(r.Context(), p)
	if err != nil {
		panelError(w, 400, err.Error())
		return
	}
	if s.metricsStarted.Load() {
		if err = s.metrics.Apply(prepared); err != nil {
			panelError(w, 503, err.Error())
			return
		}
	}
	if err = s.store.SavePanelSettings(r.Context(), p, current(r).Username, "panel.metrics.update"); err != nil {
		if s.metricsStarted.Load() {
			if previous, e := s.metricsConfig(context.Background(), old); e == nil {
				_ = s.metrics.Apply(previous)
			} else {
				s.metrics.Failure("metrics.configuration", old.MetricsMTLS)
			}
		}
		s.panelSaveError(w, err)
		return
	}
	s.invalidate("panel-settings", "audit")
	s.getPanelSettings(w, r)
}
func (s *Server) runMetrics(ctx context.Context) {
	s.metricsStarted.Store(true)
	defer s.metrics.Close()
	dir := filepath.Join(filepath.Dir(s.cfg.DBPath), "certs", "metrics")
	_ = os.MkdirAll(dir, 0700)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		s.panelMu.Lock()
		before := s.metrics.Status()
		work, cancel := context.WithTimeout(ctx, 5*time.Second)
		p, err := s.store.PanelSettings(work)
		if err == nil {
			var prepared metricsweb.Prepared
			prepared, err = s.metricsConfig(work, p)
			if err == nil {
				err = s.metrics.Apply(prepared)
			}
		}
		cancel()
		if err != nil {
			code := "metrics.configuration"
			if strings.HasPrefix(err.Error(), "metrics.") {
				code = err.Error()
			}
			s.metrics.Failure(code, true)
		}
		after := s.metrics.Status()
		s.panelMu.Unlock()
		if before != after {
			s.invalidate("panel-settings")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
