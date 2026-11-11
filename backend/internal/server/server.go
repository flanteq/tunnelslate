package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tunnelslate/internal/buildinfo"
	"tunnelslate/internal/config"
	"tunnelslate/internal/management"
	"tunnelslate/internal/metricsweb"
	"tunnelslate/internal/passwordhash"
	"tunnelslate/internal/pki"
	"tunnelslate/internal/store"
	"tunnelslate/internal/vpnauth"
	"tunnelslate/internal/vpnsettings"
)

const cookieName = "tunnelslate_session"

type sessionKey struct{}
type session struct {
	AdminID                   int64
	Username, CSRF, TokenHash string
	PasswordSetupRequired     bool
}
type bucket struct {
	Count int
	Until time.Time
}
type Server struct {
	panelMu          sync.Mutex
	metrics          *metricsweb.Manager
	metricsStarted   atomic.Bool
	statisticsAt     atomic.Int64
	events           *eventHub
	liveMu           sync.Mutex
	live             *liveSnapshot
	liveAt           time.Time
	liveKick         chan struct{}
	pkiKick          chan struct{}
	crlRenewalFailed atomic.Bool
	handler          http.Handler
	pki              *pki.Service
	management       *management.Client
	vpnSettings      *vpnsettings.Service
	vpnAuth          *vpnauth.Service
	cfg              config.Config
	store            *store.Store
	dummyHash        string
	loginMu          sync.Mutex
	attempts         map[string]bucket
	loginSlots       chan struct{}
	loginClock       func() time.Time
	totpClock        func() time.Time
}

func New(cfg config.Config, db *store.Store) (*Server, error) {
	if cfg.StatsRetentionDays == 0 {
		cfg.StatsRetentionDays = config.DefaultStatsRetentionDays
	}
	if cfg.StatsRetentionDays < 1 || cfg.StatsRetentionDays > config.MaxAuditRetentionDays {
		return nil, errors.New("STATS_RETENTION_DAYS must be an integer between 1 and 36500")
	}
	if cfg.AuditRetentionDays == 0 {
		cfg.AuditRetentionDays = config.DefaultAuditRetentionDays
	}
	if cfg.AuditRetentionDays < 1 || cfg.AuditRetentionDays > config.MaxAuditRetentionDays {
		return nil, errors.New("AUDIT_RETENTION_DAYS must be an integer between 1 and 36500")
	}
	dummy, err := passwordhash.Hash("dummy-password-for-timing-only")
	if err != nil {
		return nil, err
	}
	s := &Server{events: newEventHub(), liveKick: make(chan struct{}, 1), pkiKick: make(chan struct{}, 1), cfg: cfg, store: db, dummyHash: dummy, attempts: map[string]bucket{}, loginSlots: make(chan struct{}, 4)}
	if cfg.MetricsListen == "" {
		cfg.MetricsListen = ":9090"
		s.cfg.MetricsListen = cfg.MetricsListen
	}
	s.metrics = metricsweb.New(cfg.MetricsListen, s.metricsHandler())
	s.management = &management.Client{Socket: cfg.ManagementSocket}
	controlDir := ""
	if cfg.ManagementSocket != "" {
		controlDir = filepath.Dir(cfg.ManagementSocket)
	}
	s.vpnAuth = &vpnauth.Service{Store: db, ControlDir: controlDir, Management: s.management, Changed: s.invalidate}
	s.pki = &pki.Service{Changed: s.invalidate, Store: db, Management: s.management, PKIDir: cfg.PKIDir, RuntimeDir: cfg.OpenVPNDir, CCDDir: cfg.CCDDir}
	s.pki.PublishAuth = s.vpnAuth.Publish
	s.vpnSettings = &vpnsettings.Service{Store: db, RuntimeDir: cfg.OpenVPNDir, ControlDir: filepath.Dir(cfg.ManagementSocket), ValidateClients: s.pki.ValidateCCDNetwork, PrepareClients: s.pki.PublishCCD}
	if err := s.vpnSettings.Ensure(context.Background(), cfg); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) { jsonResponse(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]string{"version": buildinfo.Version})
	})
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /api/auth/bootstrap", s.loginBootstrap)
	mux.HandleFunc("POST /api/auth/login", s.login)
	mux.HandleFunc("POST /api/auth/totp", s.completeTOTPLogin)
	mux.Handle("POST /api/auth/totp/setup", s.auth(s.csrf(http.HandlerFunc(s.startTOTPSetup))))
	mux.Handle("POST /api/auth/totp/enable", s.auth(s.csrf(http.HandlerFunc(s.enableTOTP))))
	mux.Handle("POST /api/auth/totp/disable", s.auth(s.csrf(http.HandlerFunc(s.disableTOTP))))
	mux.HandleFunc("GET /profiles", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cfg.BasePath+"/profiles/", http.StatusPermanentRedirect)
	})
	mux.HandleFunc("POST /api/share/exchange", s.exchangeShare)
	mux.Handle("GET /api/share/session", s.shareAuth(http.HandlerFunc(s.shareSessionInfo)))
	mux.Handle("GET /api/share/devices", s.shareAuth(http.HandlerFunc(s.shareDevices)))
	mux.Handle("GET /api/share/devices/{id}/profile", s.shareAuth(http.HandlerFunc(s.shareProfile)))
	mux.Handle("POST /api/share/compromised", s.shareAuth(s.shareCSRF(http.HandlerFunc(s.shareCompromised))))
	mux.Handle("POST /api/clients/{id}/link", s.auth(s.csrf(http.HandlerFunc(s.saveClientLink))))
	mux.Handle("POST /api/clients/{id}/link/delete", s.auth(s.csrf(http.HandlerFunc(s.deleteClientLink))))
	mux.Handle("POST /api/clients/{id}/link/compromised", s.auth(s.csrf(http.HandlerFunc(s.clientLinkCompromised))))

	mux.Handle("GET /api/admins", s.auth(http.HandlerFunc(s.listAdmins)))
	mux.Handle("POST /api/admins", s.auth(s.csrf(http.HandlerFunc(s.createAdmin))))
	mux.Handle("POST /api/admins/{id}/rename", s.auth(s.csrf(http.HandlerFunc(s.renameAdmin))))
	mux.Handle("POST /api/admins/{id}/reset-password", s.auth(s.csrf(http.HandlerFunc(s.resetAdminPassword))))
	mux.Handle("POST /api/admins/{id}/delete", s.auth(s.csrf(http.HandlerFunc(s.deleteAdmin))))
	mux.Handle("POST /api/admins/{id}/end-sessions", s.auth(s.csrf(http.HandlerFunc(s.endAdminSessions))))
	mux.Handle("GET /api/events", s.auth(http.HandlerFunc(s.streamEvents)))
	mux.Handle("GET /api/auth/session", s.auth(http.HandlerFunc(s.currentSession)))
	mux.Handle("POST /api/auth/logout", s.auth(s.csrf(http.HandlerFunc(s.logout))))
	mux.Handle("POST /api/auth/password", s.auth(s.csrf(http.HandlerFunc(s.changePassword))))
	mux.Handle("POST /api/auth/setup-password", s.auth(s.csrf(http.HandlerFunc(s.setupPassword))))
	mux.Handle("GET /api/dashboard", s.auth(http.HandlerFunc(s.dashboard)))
	mux.Handle("GET /api/clients/{id}/statistics", s.auth(http.HandlerFunc(s.clientStatistics)))
	mux.Handle("GET /api/clients/{id}/statistics/devices/{device}/days", s.auth(http.HandlerFunc(s.deviceStatisticsDays)))
	mux.Handle("GET /api/clients", s.auth(http.HandlerFunc(s.clients)))
	mux.Handle("GET /api/certificates", s.auth(http.HandlerFunc(s.certificates)))
	mux.Handle("GET /api/audit", s.auth(http.HandlerFunc(s.audit)))
	mux.HandleFunc("/metrics", http.NotFound)
	mux.Handle("GET /api/panel-settings", s.auth(http.HandlerFunc(s.getPanelSettings)))
	mux.Handle("PUT /api/panel-settings/general", s.auth(s.csrf(http.HandlerFunc(s.savePanelGeneral))))
	mux.Handle("PUT /api/panel-settings/metrics", s.auth(s.csrf(http.HandlerFunc(s.saveMetricsSettings))))
	mux.Handle("GET /api/settings", s.auth(http.HandlerFunc(s.settings)))
	mux.Handle("PUT /api/settings/vpn", s.auth(s.csrf(http.HandlerFunc(s.saveVPNSettings))))
	mux.Handle("GET /api/vpn-auth/providers", s.auth(http.HandlerFunc(s.authProviders)))
	mux.Handle("POST /api/vpn-auth/providers", s.auth(s.csrf(http.HandlerFunc(s.saveAuthProvider))))
	mux.Handle("PUT /api/vpn-auth/providers/{id}", s.auth(s.csrf(http.HandlerFunc(s.saveAuthProvider))))
	mux.Handle("POST /api/vpn-auth/providers/{id}/delete", s.auth(s.csrf(http.HandlerFunc(s.deleteAuthProvider))))
	mux.Handle("POST /api/vpn-auth/providers/{id}/test", s.auth(s.csrf(http.HandlerFunc(s.testAuthProvider))))
	mux.Handle("GET /api/clients/{id}/vpn-auth", s.auth(s.authBinding(false)))
	mux.Handle("PUT /api/clients/{id}/vpn-auth", s.auth(s.csrf(s.authBinding(true))))
	mux.Handle("POST /api/pki/initialize", s.auth(s.csrf(http.HandlerFunc(s.initializePKI))))
	mux.Handle("POST /api/clients", s.auth(s.csrf(http.HandlerFunc(s.createClient))))
	mux.Handle("POST /api/clients/{id}/delete", s.auth(s.csrf(s.mutatePKI("delete_client"))))
	mux.Handle("GET /api/devices", s.auth(http.HandlerFunc(s.devices)))
	mux.Handle("GET /api/devices/{id}/ccd", s.auth(http.HandlerFunc(s.deviceCCD)))
	mux.Handle("PUT /api/devices/{id}/ccd", s.auth(s.csrf(http.HandlerFunc(s.saveDeviceCCD))))
	mux.Handle("POST /api/clients/{id}/devices", s.auth(s.csrf(s.mutatePKI("issue"))))
	mux.Handle("POST /api/devices/{id}/rotate", s.auth(s.csrf(s.mutatePKI("rotate"))))
	mux.Handle("POST /api/devices/{id}/delete", s.auth(s.csrf(s.mutatePKI("delete"))))
	mux.Handle("POST /api/certificates/{id}/revoke", s.auth(s.csrf(s.mutatePKI("revoke"))))
	mux.Handle("GET /api/devices/{id}/profile", s.auth(http.HandlerFunc(s.profile)))
	mux.Handle("GET /api/operations", s.auth(http.HandlerFunc(s.operations)))
	mux.Handle("POST /api/operations/{id}/retry", s.auth(s.csrf(http.HandlerFunc(s.retryOperation))))
	mux.Handle("GET /api/connections", s.auth(http.HandlerFunc(s.connections)))
	mux.Handle("POST /api/connections/disconnect", s.auth(s.csrf(http.HandlerFunc(s.disconnect))))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { apiError(w, 404, "API endpoint not found") })
	mux.HandleFunc("/", s.static)
	var routes http.Handler = mux
	if cfg.BasePath != "" {
		stripped := http.StripPrefix(cfg.BasePath, mux)
		routes = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" || r.URL.Path == "/livez" {
				mux.ServeHTTP(w, r)
				return
			}
			if r.URL.Path == cfg.BasePath {
				http.Redirect(w, r, cfg.BasePath+"/", http.StatusPermanentRedirect)
				return
			}
			if !strings.HasPrefix(r.URL.Path, cfg.BasePath+"/") {
				http.NotFound(w, r)
				return
			}
			stripped.ServeHTTP(w, r)
		})
	}
	s.handler = s.headers(routes)
	return s, nil
}

func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func apiError(w http.ResponseWriter, status int, message string) {
	code, params := apiErrorDetails(status, message)
	jsonResponse(w, status, map[string]any{"error": message, "code": code, "params": params})
}
func internalError(w http.ResponseWriter, action string, err error) {
	slog.Error(action, "error", err)
	apiError(w, 500, "Internal server error")
}
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		path := strings.TrimPrefix(r.URL.Path, s.cfg.BasePath)
		if strings.HasPrefix(path, "/api/") || path == "/healthz" || r.URL.Path == "/healthz" {
			w.Header().Set("Cache-Control", "no-store")
		}
		defer func() {
			if err := recover(); err != nil {
				slog.Error("request panic", "path", r.URL.Path)
				apiError(w, 500, "Internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.DB.PingContext(ctx); err != nil {
		apiError(w, 503, "Database unavailable")
		return
	}
	jsonResponse(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) validOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return origin == "" || origin == s.cfg.PublicURL
}

// A separate request budget also bounds malformed and successful requests.
func (s *Server) allowLogin(r *http.Request) bool {
	return s.allowAttempt("auth-request:"+s.loginIP(r), 60)
}

func (s *Server) allowAttempt(key string, limit int) bool {
	now := time.Now()
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	for key, b := range s.attempts {
		if now.After(b.Until) {
			delete(s.attempts, key)
		}
	}
	b, exists := s.attempts[key]
	if !exists {
		if len(s.attempts) >= 4096 {
			return false
		}
		b = bucket{Until: now.Add(5 * time.Minute)}
	}
	if b.Count >= limit {
		return false
	}
	b.Count++
	s.attempts[key] = b
	return true
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.validOrigin(r) {
		apiError(w, 403, "Origin not allowed")
		return
	}
	if !s.loginIPAllowed(w, r, s.store.DB) {
		return
	}
	if !s.allowLogin(r) {
		w.Header().Set("Retry-After", "300")
		apiError(w, 429, "Too many login attempts; try again later")
		return
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		apiError(w, 429, "Login is busy; try again later")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		apiError(w, 400, "Invalid login request")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		apiError(w, 400, "Expected one JSON object")
		return
	}
	var identity loginIdentity
	err := s.store.DB.QueryRowContext(r.Context(), `SELECT a.id,a.password_hash,a.password_setup_required,a.username,COALESCE(t.generation,'')
 FROM admins a LEFT JOIN admin_totp t ON t.admin_id=a.id WHERE a.username=?`, input.Username).Scan(&identity.ID, &identity.PasswordHash, &identity.SetupRequired, &identity.Username, &identity.TOTPGeneration)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		internalError(w, "load administrator", err)
		return
	}
	exists := err == nil
	compareHash := identity.PasswordHash
	if !exists {
		compareHash = s.dummyHash
	}
	match := passwordhash.Verify(compareHash, input.Password) == nil
	if !exists || !match {
		s.rejectLogin(w, r)
		return
	}
	if identity.TOTPGeneration != "" {
		s.beginTOTPLogin(w, r, identity)
		return
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, "begin login", err)
		return
	}
	defer tx.Rollback()
	result, err := s.newLoginSession(r, tx, identity)
	if s.respondLoginBan(w, err) {
		return
	}
	if errors.Is(err, errLoginChanged) {
		apiError(w, 401, "Invalid username or password")
		return
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		internalError(w, "save login", err)
		return
	}
	s.respondLogin(w, result)
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err != nil || len(cookie.Value) != 64 {
			apiError(w, 401, "Authentication required")
			return
		}
		current := session{TokenHash: tokenHash(cookie.Value)}
		err = s.store.DB.QueryRowContext(r.Context(), "SELECT a.id,a.username,s.csrf_token,a.password_setup_required FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>?", current.TokenHash, time.Now().Unix()).Scan(&current.AdminID, &current.Username, &current.CSRF, &current.PasswordSetupRequired)
		if errors.Is(err, sql.ErrNoRows) {
			apiError(w, 401, "Session expired; sign in again")
			return
		}
		if err != nil {
			internalError(w, "load session", err)
			return
		}
		if current.PasswordSetupRequired {
			allowed := (r.Method == "GET" && r.URL.Path == "/api/auth/session") ||
				(r.Method == "POST" && (r.URL.Path == "/api/auth/setup-password" || r.URL.Path == "/api/auth/logout"))
			if !allowed {
				jsonResponse(w, http.StatusForbidden, map[string]string{"error": "Set a permanent administrator password first", "code": "password_setup_required"})
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, current)))
	})
}
func current(r *http.Request) session { return r.Context().Value(sessionKey{}).(session) }
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.validOrigin(r) || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(current(r).CSRF)) != 1 {
			apiError(w, 403, "Invalid CSRF token or origin")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) currentSession(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	jsonResponse(w, 200, map[string]any{"id": u.AdminID, "username": u.Username, "csrf_token": u.CSRF, "password_setup_required": u.PasswordSetupRequired})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, "begin logout", err)
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE token_hash=?", u.TokenHash); err == nil {
		_, err = tx.ExecContext(r.Context(), "INSERT INTO audit_events(actor,action,created_at) VALUES (?, 'auth.logout', ?)", u.Username, time.Now().Unix())
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		internalError(w, "save logout", err)
		return
	}
	s.events.revoke(u.TokenHash)
	s.invalidate("audit", "admins")
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: s.cfg.BasePath + "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
	jsonResponse(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	var clients, devices, valid, revoked, expired int
	err := s.store.DB.QueryRowContext(r.Context(), `SELECT
      (SELECT count(*) FROM clients WHERE deleted_at IS NULL), (SELECT count(*) FROM devices WHERE deleted_at IS NULL),
      (SELECT count(*) FROM certificates c JOIN operations o ON o.id=c.operation_id WHERE c.status='valid' AND c.not_after>? AND o.state='succeeded'),
      (SELECT count(*) FROM certificates WHERE status='revoked'),
      (SELECT count(*) FROM certificates WHERE status='expired' OR (status='valid' AND not_after<=?))`, time.Now().Unix(), time.Now().Unix()).Scan(&clients, &devices, &valid, &revoked, &expired)
	if err != nil {
		internalError(w, "read dashboard", err)
		return
	}
	stats, err := s.store.ServerStatistics(r.Context(), time.Now())
	if err != nil {
		internalError(w, "read statistics", err)
		return
	}
	panel, err := s.store.PanelSettings(r.Context())
	if err != nil {
		internalError(w, "read panel settings", err)
		return
	}
	live := s.getLive(r.Context(), false)
	jsonResponse(w, 200, map[string]any{"statistics": stats, "clients": clients, "devices": devices, "valid_certificates": valid, "revoked_certificates": revoked, "expired_certificates": expired, "vpn": live.VPN, "crl": live.CRL, "version": buildinfo.Version, "instance_name": panel.InstanceName})
}

func (s *Server) clients(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.DB.QueryContext(r.Context(), "SELECT c.id,c.name,c.disabled,c.created_at,COALESCE(l.created_at,0),EXISTS(SELECT 1 FROM operations WHERE client_id=c.id AND kind='revoke_client' AND state IN ('pending','running','partial')),COALESCE(a.provider_id,'')!='',COALESCE(p.enabled,0) FROM clients c LEFT JOIN client_links l ON l.client_id=c.id LEFT JOIN client_vpn_auth a ON a.client_id=c.id LEFT JOIN vpn_auth_providers p ON p.id=a.provider_id WHERE c.deleted_at IS NULL ORDER BY c.created_at DESC")
	if err != nil {
		internalError(w, "list clients", err)
		return
	}
	defer rows.Close()
	type client struct {
		ID                  string `json:"id"`
		Name                string `json:"name"`
		Disabled            bool   `json:"disabled"`
		CreatedAt           int64  `json:"created_at"`
		LinkCreatedAt       int64  `json:"link_created_at"`
		RevocationPending   bool   `json:"revocation_pending"`
		ExternalAuth        bool   `json:"external_auth"`
		AuthProviderEnabled bool   `json:"auth_provider_enabled"`
	}
	result := []client{}
	for rows.Next() {
		var c client
		if err := rows.Scan(&c.ID, &c.Name, &c.Disabled, &c.CreatedAt, &c.LinkCreatedAt, &c.RevocationPending, &c.ExternalAuth, &c.AuthProviderEnabled); err != nil {
			internalError(w, "read client", err)
			return
		}
		result = append(result, c)
	}
	if err := rows.Err(); err != nil {
		internalError(w, "list clients", err)
		return
	}
	jsonResponse(w, 200, result)
}

func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT c.serial,d.name,c.device_id,d.client_id,u.name,c.status,c.not_after,c.revoked_at,c.common_name,COALESCE(o.state,'') FROM certificates c JOIN devices d ON d.id=c.device_id JOIN clients u ON u.id=d.client_id LEFT JOIN operations o ON o.id=c.operation_id WHERE d.deleted_at IS NULL ORDER BY c.rowid DESC`)
	if err != nil {
		internalError(w, "list certificates", err)
		return
	}
	defer rows.Close()
	type certificate struct {
		Serial         string `json:"serial"`
		Device         string `json:"device"`
		DeviceID       string `json:"device_id"`
		ClientID       string `json:"client_id"`
		Client         string `json:"client"`
		Status         string `json:"status"`
		NotAfter       int64  `json:"not_after"`
		RevokedAt      *int64 `json:"revoked_at"`
		CommonName     string `json:"common_name"`
		OperationState string `json:"operation_state"`
	}
	result := []certificate{}
	for rows.Next() {
		var c certificate
		if err := rows.Scan(&c.Serial, &c.Device, &c.DeviceID, &c.ClientID, &c.Client, &c.Status, &c.NotAfter, &c.RevokedAt, &c.CommonName, &c.OperationState); err != nil {
			internalError(w, "read certificate", err)
			return
		}
		if c.Status == "valid" && c.NotAfter <= time.Now().Unix() {
			c.Status = "expired"
		}
		result = append(result, c)
	}
	if err := rows.Err(); err != nil {
		internalError(w, "list certificates", err)
		return
	}
	jsonResponse(w, 200, result)
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.DB.QueryContext(r.Context(), "SELECT a.id,a.actor,a.action,a.target,a.created_at,a.severity,COALESCE(c.name,d.name,'') FROM audit_events a LEFT JOIN clients c ON c.id=a.target LEFT JOIN devices d ON d.id=a.target ORDER BY a.id DESC LIMIT 100")
	if err != nil {
		internalError(w, "list audit", err)
		return
	}
	defer rows.Close()
	type event struct {
		Severity   string `json:"severity"`
		TargetName string `json:"target_name"`
		ID         int64  `json:"id"`
		Actor      string `json:"actor"`
		Action     string `json:"action"`
		Target     string `json:"target"`
		CreatedAt  int64  `json:"created_at"`
	}
	result := []event{}
	for rows.Next() {
		var e event
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Target, &e.CreatedAt, &e.Severity, &e.TargetName); err != nil {
			internalError(w, "read audit", err)
			return
		}
		result = append(result, e)
	}
	if err := rows.Err(); err != nil {
		internalError(w, "list audit", err)
		return
	}
	jsonResponse(w, 200, result)
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	bootstrap, err := s.pki.InitializationStatus(r.Context())
	if err != nil {
		internalError(w, "PKI initialization status", err)
		return
	}
	vpn, err := s.vpnSettings.Get(r.Context())
	if err != nil {
		internalError(w, "read VPN settings", err)
		return
	}
	var externalVPNAuth bool
	if err := s.store.DB.QueryRowContext(r.Context(), "SELECT EXISTS(SELECT 1 FROM vpn_auth_providers WHERE enabled=1)").Scan(&externalVPNAuth); err != nil {
		internalError(w, "read VPN authentication availability", err)
		return
	}
	live := s.getLive(r.Context(), false)
	applied := live.AppliedRevision
	jsonResponse(w, 200, map[string]any{
		"bootstrap": bootstrap, "editable": true, "source": "database", "vpn": vpn, "network_status": s.vpnSettings.NetworkStatus(),
		"applied_revision":     applied,
		"certificate_max_date": s.pki.CertificateMaxDate(),
		"dco":                  live.VPN["dco"],
		"storage":              map[string]string{"database": s.cfg.DBPath, "pki": s.cfg.PKIDir, "openvpn": s.cfg.OpenVPNDir, "ccd": s.cfg.CCDDir},
		"auth":                 map[string]any{"cookie_secure": s.cfg.CookieSecure, "session_ttl": s.cfg.SessionTTL.String()},
		"capabilities":         map[string]bool{"pki": s.pki.Available(), "live_connections": s.cfg.ManagementSocket != "", "edit_vpn_settings": true, "external_vpn_auth": externalVPNAuth},
	})
}

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/index.html" {
		http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusPermanentRedirect)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		apiError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api") {
		apiError(w, 404, "API endpoint not found")
		return
	}
	path := filepath.Join(s.cfg.WebDir, filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/")))
	info, err := os.Stat(path)
	if err == nil && !info.IsDir() {
		if strings.Contains(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		http.FileServer(http.Dir(s.cfg.WebDir)).ServeHTTP(w, r)
		return
	}
	if filepath.Ext(r.URL.Path) != "" {
		http.NotFound(w, r)
		return
	}
	index := filepath.Join(s.cfg.WebDir, "index.html")
	if _, err := os.Stat(index); err != nil {
		apiError(w, 503, "Frontend not built; build the Docker image")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	if r.URL.Path == "/profiles/" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	}
	data, err := os.ReadFile(index)
	if err != nil {
		internalError(w, "read frontend", err)
		return
	}
	data = bytes.Replace(data, []byte("<head>"), []byte(`<head><base href="`+s.cfg.BasePath+`/">`), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(data))
}
