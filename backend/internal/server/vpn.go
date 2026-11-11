package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"tunnelslate/internal/ccd"
	"tunnelslate/internal/management"
	"tunnelslate/internal/pki"
	"tunnelslate/internal/vpnsettings"
)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }
func (s *Server) Run(ctx context.Context) {
	defer s.StopEvents()
	go s.runMetrics(ctx)
	go s.runLive(ctx)
	go s.runAuditRetention(ctx)
	go s.runStatistics(ctx)
	go s.runVPNAuth(ctx)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	prepared := false
	var nextCRLCheck time.Time
	for {
		work, cancel := context.WithTimeout(ctx, 90*time.Second)
		_, _ = s.store.DB.ExecContext(work, "DELETE FROM client_link_sessions WHERE expires_at<=?", time.Now().Unix())
		if err := s.store.CleanupInitialPassword(work); err != nil && ctx.Err() == nil {
			slog.Warn("Initial password file cleanup pending", "error", err)
		}
		if err := s.vpnSettings.Publish(work); err != nil && ctx.Err() == nil {
			slog.Warn("VPN settings publication pending", "error", err)
		}
		if !prepared {
			if err := s.pki.PrepareExisting(work); err != nil && ctx.Err() == nil {
				slog.Warn("Existing PKI needs attention", "error", err)
			} else {
				prepared = true
			}
		}
		if now := time.Now(); !now.Before(nextCRLCheck) && work.Err() == nil {
			nextCRLCheck = now.Add(s.maintainCRL(work, now))
		}
		if err := s.pki.Recover(work); err != nil && ctx.Err() == nil {
			slog.Warn("PKI recovery pending", "error", err)
		}
		if err := s.pki.PublishCCD(work); err != nil && ctx.Err() == nil {
			slog.Warn("CCD publication pending", "error", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.pkiKick:
		}
	}
}

func (s *Server) initializePKI(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !decodeBody(w, r, &input) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if err := s.pki.Initialize(ctx, current(r).Username); err != nil {
		domainError(w, err)
		return
	}
	status, err := s.pki.InitializationStatus(ctx)
	if err != nil {
		internalError(w, "PKI status", err)
		return
	}
	jsonResponse(w, 200, status)
}

func decodeBody(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		apiError(w, 400, "Invalid JSON request")
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		apiError(w, 400, "Expected one JSON object")
		return false
	}
	return true
}
func domainError(w http.ResponseWriter, err error) {
	var expected *pki.Error
	if errors.As(err, &expected) {
		apiError(w, expected.Code, expected.Message)
	} else {
		internalError(w, "VPN operation", err)
	}
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if !pki.ValidName(input.Name) {
		apiError(w, 400, "Name must be 1–128 bytes without control characters")
		return
	}
	id, err := pki.NewID()
	if err != nil {
		internalError(w, "generate client ID", err)
		return
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, "begin client creation", err)
		return
	}
	defer tx.Rollback()
	var duplicate int
	if err := tx.QueryRowContext(r.Context(), "SELECT count(*) FROM clients WHERE name=? COLLATE NOCASE AND deleted_at IS NULL", input.Name).Scan(&duplicate); err != nil {
		internalError(w, "check client name", err)
		return
	}
	if duplicate > 0 {
		apiError(w, 409, "A client with this name already exists")
		return
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO clients(id,name,created_at) VALUES (?,?,?)", id, input.Name, now); err != nil {
		internalError(w, "create client", err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO audit_events(actor,action,target,created_at) VALUES (?,'client.create',?,?)", current(r).Username, id, now); err != nil {
		internalError(w, "audit client creation", err)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w, "commit client", err)
		return
	}
	s.invalidate("clients", "dashboard", "audit")
	jsonResponse(w, 201, map[string]any{"id": id, "name": input.Name, "disabled": false, "created_at": now})
}

func (s *Server) mutatePKI(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name, expiresOn, target := "", "", r.PathValue("id")
		if kind == "issue" || kind == "rotate" {
			var input struct {
				Name      string `json:"name"`
				ExpiresOn string `json:"expires_on"`
			}
			if !decodeBody(w, r, &input) {
				return
			}
			name, expiresOn = input.Name, input.ExpiresOn
			if kind == "rotate" && name != "" {
				apiError(w, 400, "При перевыпуске имя устройства не изменяется")
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		op, err := s.pki.StartWithExpiry(ctx, current(r).Username, r.Header.Get("Idempotency-Key"), kind, target, name, expiresOn)
		s.operationResponse(w, op, err)
	}
}
func (s *Server) operationResponse(w http.ResponseWriter, op pki.Operation, err error) {
	if err == nil {
		jsonResponse(w, 200, map[string]any{"operation": op})
		return
	}
	if op.State == "failed" {
		domainError(w, err)
		return
	}
	if op.ID != "" {
		code, params := apiErrorDetails(503, "Operation unfinished; see its saved status and retry")
		jsonResponse(w, 503, map[string]any{"error": "Operation unfinished; see its saved status and retry", "code": code, "params": params, "operation": op})
		return
	}
	domainError(w, err)
}
func (s *Server) retryOperation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	op, err := s.pki.Run(ctx, r.PathValue("id"))
	s.operationResponse(w, op, err)
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT d.id,d.client_id,d.name,d.created_at,COALESCE(c.serial,''),COALESCE(c.status,'pending'),COALESCE(c.not_after,0),COALESCE(c.revoked_at,0),COALESCE(c.common_name,''),COALESCE(co.state,o.state,''),COALESCE(co.id,o.id,''),COALESCE(co.kind,o.kind,''),COALESCE(x.configuration,''),COALESCE(x.static_ip,''),CASE WHEN x.device_id IS NULL THEN 0 ELSE x.revision!=x.published_revision OR x.published_vpn_revision!=(SELECT revision FROM vpn_settings WHERE id=1) OR x.publication_error!='' END FROM devices d LEFT JOIN certificates c ON c.serial=(SELECT serial FROM certificates x WHERE x.device_id=d.id ORDER BY x.rowid DESC LIMIT 1) LEFT JOIN operations o ON o.id=(SELECT id FROM operations x WHERE x.device_id=d.id ORDER BY x.rowid DESC LIMIT 1) LEFT JOIN operations co ON co.id=(SELECT id FROM operations x WHERE x.client_id=d.client_id AND x.kind IN ('delete_client','revoke_client') AND x.state IN ('pending','running','partial') ORDER BY x.rowid DESC LIMIT 1) LEFT JOIN device_ccd x ON x.device_id=d.id WHERE d.deleted_at IS NULL ORDER BY d.created_at DESC`)
	if err != nil {
		internalError(w, "list devices", err)
		return
	}
	defer rows.Close()
	type device struct {
		ID             string `json:"id"`
		ClientID       string `json:"client_id"`
		Name           string `json:"name"`
		CreatedAt      int64  `json:"created_at"`
		Serial         string `json:"serial"`
		Status         string `json:"status"`
		NotAfter       int64  `json:"not_after"`
		RevokedAt      int64  `json:"revoked_at"`
		CommonName     string `json:"common_name"`
		OperationState string `json:"operation_state"`
		OperationID    string `json:"operation_id"`
		OperationKind  string `json:"operation_kind"`
		CustomCCD      bool   `json:"custom_ccd"`
		StaticIP       string `json:"static_ip"`
		CCDPending     bool   `json:"ccd_pending"`
	}
	result := []device{}
	for rows.Next() {
		var d device
		var data string
		if err := rows.Scan(&d.ID, &d.ClientID, &d.Name, &d.CreatedAt, &d.Serial, &d.Status, &d.NotAfter, &d.RevokedAt, &d.CommonName, &d.OperationState, &d.OperationID, &d.OperationKind, &data, &d.StaticIP, &d.CCDPending); err != nil {
			internalError(w, "read device", err)
			return
		}
		if data != "" {
			var value ccd.Settings
			if err := json.Unmarshal([]byte(data), &value); err != nil {
				internalError(w, "read device CCD", err)
				return
			}
			d.CustomCCD = ccd.Customized(value)
		}
		if d.Status == "valid" && d.NotAfter <= time.Now().Unix() {
			d.Status = "expired"
		}
		result = append(result, d)
	}
	if err := rows.Err(); err != nil {
		internalError(w, "list devices", err)
		return
	}
	jsonResponse(w, 200, result)
}

func (s *Server) operations(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.DB.QueryContext(r.Context(), "SELECT o.id,o.kind,o.state,o.step,COALESCE(o.device_id,''),o.actor,o.result_serial,o.error,o.created_at,o.updated_at,COALESCE(d.name,''),COALESCE(o.client_id,d.client_id,''),COALESCE(c.name,'') FROM operations o LEFT JOIN devices d ON d.id=o.device_id LEFT JOIN clients c ON c.id=COALESCE(o.client_id,d.client_id) ORDER BY o.rowid DESC")
	if err != nil {
		internalError(w, "list operations", err)
		return
	}
	defer rows.Close()
	result := []pki.Operation{}
	for rows.Next() {
		var op pki.Operation
		if err := rows.Scan(&op.ID, &op.Kind, &op.State, &op.Step, &op.DeviceID, &op.Actor, &op.ResultSerial, &op.Error, &op.CreatedAt, &op.UpdatedAt, &op.DeviceName, &op.ClientID, &op.ClientName); err != nil {
			internalError(w, "read operation", err)
			return
		}
		result = append(result, op)
	}
	if err := rows.Err(); err != nil {
		internalError(w, "list operations", err)
		return
	}
	jsonResponse(w, 200, result)
}

func (s *Server) profile(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	vpn, err := s.vpnSettings.Get(ctx)
	if err != nil {
		internalError(w, "read profile settings", err)
		return
	}
	profile, err := s.pki.Profile(ctx, r.PathValue("id"), vpn.Endpoint, vpn.ExternalPort, vpn.Protocol, current(r).Username, vpn.Link())
	if err != nil {
		domainError(w, err)
		return
	}
	s.invalidate("audit")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": profile.Filename}))
	w.Header().Set("Content-Type", "application/x-openvpn-profile")
	w.WriteHeader(200)
	_, _ = w.Write(profile.Content)
}

func (s *Server) saveVPNSettings(w http.ResponseWriter, r *http.Request) {
	var input vpnsettings.Settings
	if !decodeBody(w, r, &input) {
		return
	}
	result, err := s.vpnSettings.Save(r.Context(), input, current(r).Username)
	if err != nil {
		domainError(w, err)
		return
	}
	s.invalidate("settings", "devices", "audit")
	jsonResponse(w, 200, result)
}

func (s *Server) deviceCCD(w http.ResponseWriter, r *http.Request) {
	view, err := s.pki.DeviceCCD(r.Context(), r.PathValue("id"))
	if err != nil {
		domainError(w, err)
		return
	}
	jsonResponse(w, 200, view)
}

func (s *Server) saveDeviceCCD(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Settings    ccd.Settings `json:"settings"`
		VPNRevision int64        `json:"vpn_revision"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	view, err := s.pki.SaveDeviceCCD(ctx, r.PathValue("id"), input.Settings, input.VPNRevision, current(r).Username)
	if err != nil {
		domainError(w, err)
		return
	}
	jsonResponse(w, 200, view)
}

func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CommonName string `json:"common_name"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if !management.ValidCN(input.CommonName) {
		apiError(w, 400, "Invalid managed certificate name")
		return
	}
	var count int
	if err := s.store.DB.QueryRowContext(r.Context(), "SELECT count(*) FROM certificates WHERE common_name=?", input.CommonName).Scan(&count); err != nil {
		internalError(w, "find connection", err)
		return
	}
	if count == 0 {
		apiError(w, 404, "Managed certificate not found")
		return
	}
	if err := s.management.Disconnect(r.Context(), input.CommonName); err != nil {
		apiError(w, 503, "Could not confirm disconnection")
		return
	}
	if err := s.store.Audit(r.Context(), current(r).Username, "session.disconnect", input.CommonName); err != nil {
		internalError(w, "audit disconnect", err)
		return
	}
	s.invalidate("connections", "audit")
	jsonResponse(w, 200, map[string]string{"status": "disconnected"})
}
