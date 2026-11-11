package server

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"time"

	"tunnelslate/internal/management"
	"tunnelslate/internal/pki"
	"tunnelslate/internal/vpnsettings"
)

type liveConnection struct {
	management.Connection
	Device string `json:"device"`
	Client string `json:"client"`
}
type liveSnapshot struct {
	NetworkState    vpnsettings.NetworkState
	VPN             map[string]any
	Connections     []liveConnection
	AppliedRevision int64
	PKIReady        bool
	Expired         int64
	CRL             pki.CRLStatus
}

// All HTTP handlers and SSE readers share a single Management Interface sample.
// The mutex also coalesces simultaneous requests immediately after startup.
func (s *Server) getLive(ctx context.Context, force bool) *liveSnapshot {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	if s.live != nil && !force && time.Since(s.liveAt) < 5*time.Second {
		return s.live
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	state := "unavailable"
	ready := s.pki.Available()
	if s.cfg.ManagementSocket == "" {
		state = "not_configured"
	} else if !ready {
		state = "waiting_for_pki"
	}
	next := &liveSnapshot{VPN: map[string]any{"state": state, "connected_clients": nil}, Connections: []liveConnection{}, PKIReady: ready}
	next.NetworkState = s.vpnSettings.NetworkStatus()
	next.CRL = s.crlStatus(time.Now())
	status, err := s.management.ReadStatus(ctx)
	if err == nil {
		next.VPN = map[string]any{"state": "connected", "connected_clients": len(status.Connections)}
		if status.Version != "" {
			next.VPN["version"] = status.Version
		}
		next.AppliedRevision = s.vpnSettings.AppliedRevision()
		for _, connection := range status.Connections {
			entry := liveConnection{Connection: connection}
			var expiresAt int64
			err := s.store.DB.QueryRowContext(ctx, "SELECT d.name,c.name,x.not_after FROM certificates x JOIN devices d ON d.id=x.device_id JOIN clients c ON c.id=d.client_id WHERE x.common_name=?", connection.CommonName).Scan(&entry.Device, &entry.Client, &expiresAt)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				entry.Device = ""
				entry.Client = ""
			}
			if err == nil && expiresAt <= time.Now().Unix() && management.ValidCN(connection.CommonName) {
				if disconnectErr := s.management.Disconnect(ctx, connection.CommonName); disconnectErr != nil {
					slog.Warn("Expired VPN session disconnect pending", "common_name", connection.CommonName, "error", disconnectErr)
				} else {
					if _, auditErr := s.store.DB.ExecContext(ctx, "INSERT INTO audit_events(actor,action,target,created_at) VALUES ('system','session.expired',?,?)", connection.CommonName, time.Now().Unix()); auditErr != nil {
						slog.Error("Audit expired VPN session", "error", auditErr)
					} else {
						s.events.invalidate("audit")
					}
					continue
				}
			}
			next.Connections = append(next.Connections, entry)
		}
		next.VPN["connected_clients"] = len(next.Connections)
	}
	next.VPN["dco"] = s.vpnSettings.DCOStatus(ctx, err == nil, status.DCOEnabled, status.DCOSupported, next.AppliedRevision)
	old := s.live
	if old != nil {
		next.Expired = old.Expired
	}
	_ = s.store.DB.QueryRowContext(ctx, "SELECT count(*) FROM certificates WHERE status='valid' AND not_after<=?", time.Now().Unix()).Scan(&next.Expired)
	if ctx.Err() != nil {
		if old != nil {
			return old
		}
		return next
	}
	s.live, s.liveAt = next, time.Now()
	if old != nil {
		if old.CRL != next.CRL {
			s.events.invalidate("dashboard")
		}
		if !reflect.DeepEqual(old.Connections, next.Connections) || !reflect.DeepEqual(old.VPN, next.VPN) {
			s.events.invalidate("connections")
		}
		if old.AppliedRevision != next.AppliedRevision || old.PKIReady != next.PKIReady || old.NetworkState != next.NetworkState {
			s.events.invalidate("settings")
		}
		if old.Expired != next.Expired {
			s.events.invalidate("dashboard", "certificates", "devices")
		}
	}
	return next
}

func (s *Server) runLive(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var consoleAdminEvent int64
	for {
		if ctx.Err() != nil {
			return
		}
		if err := s.expireAdminSessions(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("Expired administrator session cleanup pending", "error", err)
		}
		if err := s.syncConsoleAdmins(ctx, &consoleAdminEvent); err != nil && ctx.Err() == nil {
			slog.Warn("Console administrator change notification pending", "error", err)
		}
		s.getLive(ctx, true)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.liveKick:
		}
	}
}

// Console commands commit in a separate process. Reuse the shared live worker
// to notify open panels and revalidate streams belonging to reset accounts.
func (s *Server) syncConsoleAdmins(ctx context.Context, previous *int64) error {
	var latest int64
	err := s.store.DB.QueryRowContext(ctx, `SELECT COALESCE(MAX(id),0) FROM audit_events
 WHERE actor='system:console' AND action IN ('admin.created','admin.password.reset','admin.totp.reset')`).Scan(&latest)
	if err != nil {
		return err
	}
	if latest != *previous {
		*previous = latest
		s.invalidate("admins", "audit", "dashboard")
	}
	return nil
}

func (s *Server) vpnStatus(ctx context.Context) map[string]any { return s.getLive(ctx, false).VPN }
func (s *Server) connections(w http.ResponseWriter, r *http.Request) {
	live := s.getLive(r.Context(), false)
	if live.VPN["state"] != "connected" {
		apiError(w, 503, "OpenVPN management is unavailable")
		return
	}
	jsonResponse(w, 200, live.Connections)
}
