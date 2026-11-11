package server

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"tunnelslate/internal/branding"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"tunnelslate/internal/buildinfo"
	"tunnelslate/internal/vpnsettings"
)

type vpnCollector struct{ server *Server }

// Unchecked collector: all metric families are described consistently in Collect.
func (*vpnCollector) Describe(chan<- *prometheus.Desc) {}
func (c *vpnCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	emit := func(name, help string, kind prometheus.ValueType, v float64, labels []string, values ...string) {
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc(branding.MetricsPrefix+name, help, labels, nil), kind, v, values...)
	}
	gauge := func(name, help string, v float64) { emit(name, help, prometheus.GaugeValue, v, nil) }
	component := func(name string, up bool) {
		emit("component_up", "Component health; 1 means healthy.", prometheus.GaugeValue, boolFloat(up), []string{"component"}, name)
	}
	// Build database-derived families as a coherent snapshot. Do not publish a
	// partially read set of totals as though it were complete on a database error.
	var metrics []prometheus.Metric
	dbEmit := func(name, help string, kind prometheus.ValueType, v float64, labels []string, values ...string) {
		metrics = append(metrics, prometheus.MustNewConstMetric(prometheus.NewDesc(branding.MetricsPrefix+name, help, labels, nil), kind, v, values...))
	}
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		component("database", false)
		gauge("metrics_collection_success", "Whether the complete monitoring snapshot was read.", 0)
		return
	}
	defer tx.Rollback()
	var instance string
	err = tx.QueryRowContext(ctx, "SELECT instance_name FROM panel_settings WHERE id=1").Scan(&instance)
	if err == nil {
		var rowsErr error
		rows, e := tx.QueryContext(ctx, `SELECT t.kind,t.entity_id,COALESCE(c.name,u.name,''),COALESCE(d.id,''),COALESCE(d.name,''),t.sessions,t.duration_seconds,t.bytes_received,t.bytes_sent FROM vpn_stat_totals t LEFT JOIN clients c ON t.kind='client' AND c.id=t.entity_id LEFT JOIN devices d ON t.kind='device' AND d.id=t.entity_id LEFT JOIN clients u ON u.id=d.client_id WHERE t.kind='server' OR (t.kind='client' AND c.deleted_at IS NULL AND c.id IS NOT NULL) OR (t.kind='device' AND d.deleted_at IS NULL AND u.deleted_at IS NULL AND d.id IS NOT NULL)`)
		if e != nil {
			err = e
		} else {
			for rows.Next() {
				var kind, id, client, deviceID, device string
				var sessions, duration, rx, tx int64
				if rowsErr = rows.Scan(&kind, &id, &client, &deviceID, &device, &sessions, &duration, &rx, &tx); rowsErr != nil {
					break
				}
				prefix := "vpn_"
				var labels, values []string
				switch kind {
				case "client":
					prefix = "client_"
					labels = []string{"client_id", "client"}
					values = []string{id, client}
				case "device":
					prefix = "profile_"
					labels = []string{"device_id", "device", "client"}
					values = []string{deviceID, device, client}
				}
				dbEmit(prefix+"sessions_total", "Lifetime VPN sessions, independently persisted.", prometheus.CounterValue, float64(sessions), labels, values...)
				dbEmit(prefix+"duration_seconds_total", "Lifetime sum of VPN session durations, in seconds.", prometheus.CounterValue, float64(duration), labels, values...)
				dl := append(append([]string{}, labels...), "direction")
				dbEmit(prefix+"traffic_bytes_total", "Lifetime VPN traffic in bytes, from the client perspective.", prometheus.CounterValue, float64(rx), dl, append(append([]string{}, values...), "received")...)
				dbEmit(prefix+"traffic_bytes_total", "Lifetime VPN traffic in bytes, from the client perspective.", prometheus.CounterValue, float64(tx), dl, append(append([]string{}, values...), "sent")...)
			}
			if rowsErr == nil {
				rowsErr = rows.Err()
			}
			rows.Close()
			err = rowsErr
		}
	}
	if err == nil {
		rows, e := tx.QueryContext(ctx, `SELECT u.id,u.name,d.id,d.name,c.serial,c.status,c.not_after FROM devices d JOIN clients u ON u.id=d.client_id JOIN certificates c ON c.serial=(SELECT serial FROM certificates x WHERE x.device_id=d.id ORDER BY x.rowid DESC LIMIT 1) LEFT JOIN operations o ON o.id=c.operation_id WHERE d.deleted_at IS NULL AND u.deleted_at IS NULL AND COALESCE(o.state,'succeeded')='succeeded'`)
		if e != nil {
			err = e
		} else {
			for rows.Next() {
				var clientID, client, deviceID, device, serial, status string
				var expiry int64
				if err = rows.Scan(&clientID, &client, &deviceID, &device, &serial, &status, &expiry); err != nil {
					break
				}
				labels := []string{"client_id", "client", "device_id", "device", "serial"}
				values := []string{clientID, client, deviceID, device, serial}
				if status == "valid" && expiry <= time.Now().Unix() {
					status = "expired"
				}
				dbEmit("profile_certificate_status", "Status of the current profile certificate (one series per profile).", prometheus.GaugeValue, 1, append(labels, "status"), append(values, status)...)
				if status != "revoked" {
					dbEmit("profile_certificate_not_after_timestamp_seconds", "Expiry of a current, non-revoked profile certificate, as a Unix timestamp.", prometheus.GaugeValue, float64(expiry), labels, values...)
				}
			}
			if err == nil {
				err = rows.Err()
			}
			rows.Close()
		}
	}
	if err == nil {
		rows, e := tx.QueryContext(ctx, "SELECT scope,value FROM monitoring_counters")
		if e != nil {
			err = e
		} else {
			for rows.Next() {
				var scope string
				var n int64
				if err = rows.Scan(&scope, &n); err != nil {
					break
				}
				dbEmit("authentication_failures_total", "Failed authentication attempts since monitoring support was installed; independent of audit retention.", prometheus.CounterValue, float64(n), []string{"scope"}, scope)
			}
			if err == nil {
				err = rows.Err()
			}
			rows.Close()
		}
	}
	if err == nil {
		rows, e := tx.QueryContext(ctx, "SELECT kind,state,count(*) FROM operations WHERE state IN ('pending','running','partial','failed') GROUP BY kind,state")
		if e != nil {
			err = e
		} else {
			for rows.Next() {
				var kind, state string
				var n int64
				if err = rows.Scan(&kind, &state, &n); err != nil {
					break
				}
				dbEmit("pki_operations", "Unfinished or failed PKI operations.", prometheus.GaugeValue, float64(n), []string{"kind", "state"}, kind, state)
			}
			if err == nil {
				err = rows.Err()
			}
			rows.Close()
		}
	}
	if err == nil {
		for _, table := range []string{"clients", "devices"} {
			var n int64
			err = tx.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE deleted_at IS NULL").Scan(&n)
			if err != nil {
				break
			}
			dbEmit(table, "Number of non-deleted "+table+".", prometheus.GaugeValue, float64(n), nil)
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		component("database", false)
		gauge("metrics_collection_success", "Whether the complete monitoring snapshot was read.", 0)
		return
	}
	for _, m := range metrics {
		ch <- m
	}
	component("database", true)
	emit("build_info", "Panel build and configured instance name.", prometheus.GaugeValue, 1, []string{"version", "instance_name"}, buildinfo.Version, instance)
	// Reuse the live worker's cache; scraping never opens another management connection.
	s.liveMu.Lock()
	live := s.live
	liveAt := s.liveAt
	s.liveMu.Unlock()
	fresh := live != nil && time.Since(liveAt) < 20*time.Second
	gauge("metrics_collection_success", "Whether the complete monitoring snapshot was read.", boolFloat(fresh))
	gauge("snapshot_timestamp_seconds", "Timestamp of the cached OpenVPN snapshot.", unixFloat(liveAt))
	up := fresh && live.VPN["state"] == "connected"
	component("openvpn", up)
	gauge("vpn_up", "Whether OpenVPN is reachable through the management interface.", boolFloat(up))
	if fresh {
		component("pki", live.PKIReady)
		component("crl", live.CRL.State == "valid" || live.CRL.State == "renewal_due")
		if live.CRL.NextUpdate > 0 {
			gauge("crl_next_update_timestamp_seconds", "Expiry of the CRL, as a Unix timestamp.", float64(live.CRL.NextUpdate))
		}
		if up {
			gauge("vpn_connections", "Number of current VPN connections.", float64(len(live.Connections)))
			if version, ok := live.VPN["version"].(string); ok {
				emit("openvpn_info", "OpenVPN version.", prometheus.GaugeValue, 1, []string{"version"}, version)
			}
			if dco, ok := live.VPN["dco"].(vpnsettings.DCOStatus); ok && dco.State != "unknown" {
				gauge("vpn_dco_active", "Whether OpenVPN reports DCO in use.", boolFloat(dco.State == "active"))
			}
		}
	}
	last := s.statisticsAt.Load()
	component("statistics", last > 0 && time.Now().Unix()-last < 30)
	gauge("statistics_last_success_timestamp_seconds", "Last successful statistics ingestion pass.", float64(last))
	for _, cert := range []struct{ kind, path string }{{"ca", filepath.Join(s.cfg.PKIDir, "easyrsa", "ca.crt")}, {"server", filepath.Join(s.cfg.OpenVPNDir, "server.crt")}} {
		if expiry, ok := certificateExpiry(cert.path); ok {
			emit("certificate_not_after_timestamp_seconds", "Expiry of infrastructure certificates, as a Unix timestamp.", prometheus.GaugeValue, float64(expiry), []string{"kind"}, cert.kind)
		}
	}
	if expires := s.metrics.Status().CertificateExpires; expires > 0 {
		emit("certificate_not_after_timestamp_seconds", "Expiry of infrastructure certificates, as a Unix timestamp.", prometheus.GaugeValue, float64(expires), []string{"kind"}, "metrics")
	}
}
func boolFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
func unixFloat(v time.Time) float64 {
	if v.IsZero() {
		return 0
	}
	return float64(v.Unix())
}
func certificateExpiry(path string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for len(b) > 0 {
		block, rest := pem.Decode(b)
		if block == nil {
			return 0, false
		}
		b = rest
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				return c.NotAfter.Unix(), true
			}
		}
	}
	return 0, false
}
func (s *Server) metricsHandler() http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}), &vpnCollector{s})
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{MaxRequestsInFlight: 2, Timeout: 10 * time.Second})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		handler.ServeHTTP(w, r)
	})
}
