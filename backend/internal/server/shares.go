package server

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"mime"
	"net"
	"net/http"
	"regexp"
	"time"
)

const shareCookieName = "tunnelslate_client_session"
const shareLifetime = 30 * time.Minute

var shareTokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type shareKey struct{}
type shareSession struct{ ClientID, Name, LinkHash, TokenHash, CSRF string }

// The token is delivered in a fragment, then exchanged through a JSON body.
// Neither the initial document URL nor later download URLs contain the secret.
func (s *Server) exchangeShare(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != s.cfg.PublicURL {
		apiError(w, 403, "Origin not allowed")
		return
	}
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if !s.allowAttempt("share-exchange:"+peer, 30) {
		w.Header().Set("Retry-After", "300")
		apiError(w, 429, "Too many requests; try again later")
		return
	}
	var input struct {
		Token string `json:"token"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if !shareTokenPattern.MatchString(input.Token) {
		apiError(w, 401, "Client link is unavailable")
		return
	}
	hash := tokenHash(input.Token)
	input.Token = ""
	token, err := randomToken()
	if err != nil {
		internalError(w, "generate client session", err)
		return
	}
	csrf, err := randomToken()
	if err != nil {
		internalError(w, "generate client CSRF token", err)
		return
	}
	s.store.LinkMu.RLock()
	defer s.store.LinkMu.RUnlock()
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, "begin client session", err)
		return
	}
	defer tx.Rollback()
	var clientID, name string
	err = tx.QueryRowContext(r.Context(), `SELECT c.id,c.name FROM client_links l JOIN clients c ON c.id=l.client_id WHERE l.token_hash=? AND c.disabled=0 AND c.deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM operations WHERE client_id=c.id AND kind IN ('delete_client','revoke_client') AND state IN ('pending','running','partial'))`, hash).Scan(&clientID, &name)
	if errors.Is(err, sql.ErrNoRows) {
		apiError(w, 401, "Client link is unavailable")
		return
	}
	if err != nil {
		internalError(w, "load client link", err)
		return
	}
	if !s.allowAttempt("share-client-exchange:"+clientID, 120) {
		w.Header().Set("Retry-After", "300")
		apiError(w, 429, "Too many requests; try again later")
		return
	}
	now := time.Now()
	if _, err := tx.ExecContext(r.Context(), "DELETE FROM client_link_sessions WHERE expires_at<=?", now.Unix()); err != nil {
		internalError(w, "clean client sessions", err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO client_link_sessions(token_hash,client_id,link_hash,csrf_token,expires_at) VALUES (?,?,?,?,?)", tokenHash(token), clientID, hash, csrf, now.Add(shareLifetime).Unix()); err != nil {
		internalError(w, "save client session", err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO audit_events(actor,action,target,created_at) VALUES (?,'client.link.open',?,?)", "client-link:"+clientID, clientID, now.Unix()); err != nil {
		internalError(w, "audit client link access", err)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w, "commit client session", err)
		return
	}
	s.invalidate("audit")
	http.SetCookie(w, &http.Cookie{Name: shareCookieName, Value: token, Path: s.cfg.BasePath + "/api/share/", HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: int(shareLifetime.Seconds()), Expires: now.Add(shareLifetime)})
	jsonResponse(w, 200, map[string]string{"client_id": clientID, "name": name, "csrf_token": csrf})
}

func (s *Server) loadShare(ctx context.Context, hash string) (shareSession, error) {
	u := shareSession{TokenHash: hash}
	err := s.store.DB.QueryRowContext(ctx, `SELECT c.id,c.name,l.token_hash,p.csrf_token FROM client_link_sessions p JOIN client_links l ON l.client_id=p.client_id AND l.token_hash=p.link_hash JOIN clients c ON c.id=l.client_id WHERE p.token_hash=? AND p.expires_at>? AND c.disabled=0 AND c.deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM operations WHERE client_id=c.id AND kind IN ('delete_client','revoke_client') AND state IN ('pending','running','partial'))`, hash, time.Now().Unix()).Scan(&u.ClientID, &u.Name, &u.LinkHash, &u.CSRF)
	return u, err
}

func (s *Server) shareAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(shareCookieName)
		if err != nil || !shareTokenPattern.MatchString(cookie.Value) {
			apiError(w, 401, "Client link is unavailable")
			return
		}
		u, err := s.loadShare(r.Context(), tokenHash(cookie.Value))
		if errors.Is(err, sql.ErrNoRows) {
			apiError(w, 401, "Client link is unavailable")
			return
		}
		if err != nil {
			internalError(w, "load client session", err)
			return
		}
		if !s.allowAttempt("share-read:"+u.ClientID, 300) {
			w.Header().Set("Retry-After", "300")
			apiError(w, 429, "Too many requests; try again later")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), shareKey{}, u)))
	})
}
func currentShare(r *http.Request) shareSession { return r.Context().Value(shareKey{}).(shareSession) }
func (s *Server) shareCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != s.cfg.PublicURL || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(currentShare(r).CSRF)) != 1 {
			apiError(w, 403, "Invalid CSRF token or origin")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Call only after slow PKI work has released its lock. Revalidate before sending
// private bytes so a download queued before revocation cannot use a stale grant.
func (s *Server) shareResponse(w http.ResponseWriter, r *http.Request, send func()) {
	s.store.LinkMu.RLock()
	defer s.store.LinkMu.RUnlock()
	u, err := s.loadShare(r.Context(), currentShare(r).TokenHash)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && u.LinkHash != currentShare(r).LinkHash) {
		apiError(w, 401, "Client link is unavailable")
		return
	}
	if err != nil {
		internalError(w, "recheck client access", err)
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
	send()
}

func (s *Server) shareSessionInfo(w http.ResponseWriter, r *http.Request) {
	u := currentShare(r)
	s.shareResponse(w, r, func() {
		jsonResponse(w, 200, map[string]string{"client_id": u.ClientID, "name": u.Name, "csrf_token": u.CSRF})
	})
}

func (s *Server) shareDevices(w http.ResponseWriter, r *http.Request) {
	u := currentShare(r)
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT d.id,d.name,COALESCE(c.status,'pending'),COALESCE(c.not_after,0),COALESCE(c.revoked_at,0),CASE WHEN c.status='valid' AND c.not_after>? AND o.state='succeeded' AND NOT EXISTS(SELECT 1 FROM operations p WHERE p.device_id=d.id AND p.state IN ('pending','running','partial')) THEN 1 ELSE 0 END FROM devices d LEFT JOIN certificates c ON c.serial=(SELECT serial FROM certificates x WHERE x.device_id=d.id ORDER BY x.rowid DESC LIMIT 1) LEFT JOIN operations o ON o.id=c.operation_id WHERE d.client_id=? AND d.deleted_at IS NULL ORDER BY d.name COLLATE NOCASE,d.id`, time.Now().Unix(), u.ClientID)
	if err != nil {
		internalError(w, "list client profiles", err)
		return
	}
	type device struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		Status       string `json:"status"`
		NotAfter     int64  `json:"not_after"`
		RevokedAt    int64  `json:"revoked_at"`
		Downloadable bool   `json:"downloadable"`
	}
	result := []device{}
	for rows.Next() {
		var d device
		if err := rows.Scan(&d.ID, &d.Name, &d.Status, &d.NotAfter, &d.RevokedAt, &d.Downloadable); err != nil {
			rows.Close()
			internalError(w, "read client profile", err)
			return
		}
		if d.Status == "valid" && d.NotAfter <= time.Now().Unix() {
			d.Status = "expired"
		}
		result = append(result, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		internalError(w, "list client profiles", err)
		return
	}
	s.shareResponse(w, r, func() { jsonResponse(w, 200, map[string]any{"name": u.Name, "devices": result}) })
}

func (s *Server) shareProfile(w http.ResponseWriter, r *http.Request) {
	u := currentShare(r)
	var owned bool
	if err := s.store.DB.QueryRowContext(r.Context(), "SELECT EXISTS(SELECT 1 FROM devices WHERE id=? AND client_id=? AND deleted_at IS NULL)", r.PathValue("id"), u.ClientID).Scan(&owned); err != nil {
		internalError(w, "check profile ownership", err)
		return
	}
	if !owned {
		apiError(w, 404, "Profile not found")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	vpn, err := s.vpnSettings.Get(ctx)
	if err != nil {
		internalError(w, "read profile settings", err)
		return
	}
	profile, err := s.pki.Profile(ctx, r.PathValue("id"), vpn.Endpoint, vpn.ExternalPort, vpn.Protocol, "client-link:"+u.ClientID, vpn.Link())
	if err != nil {
		domainError(w, err)
		return
	}
	s.invalidate("audit")
	s.shareResponse(w, r, func() {
		var valid bool
		if err := s.store.DB.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM certificates c JOIN devices d ON d.id=c.device_id WHERE c.serial=? AND d.client_id=? AND c.status='valid' AND c.not_after>? AND NOT EXISTS(SELECT 1 FROM operations WHERE device_id=d.id AND state IN ('pending','running','partial')))`, profile.Serial, u.ClientID, time.Now().Unix()).Scan(&valid); err != nil {
			internalError(w, "recheck profile certificate", err)
			return
		}
		if !valid {
			apiError(w, 409, "Profile changed; reload the list")
			return
		}
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": profile.Filename}))
		w.Header().Set("Content-Type", "application/x-openvpn-profile")
		w.WriteHeader(200)
		_, _ = w.Write(profile.Content)
	})
}

func (s *Server) shareCompromised(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !decodeBody(w, r, &input) {
		return
	}
	u := currentShare(r)
	_, err := s.pki.ReportCompromise(r.Context(), "client-link:"+u.ClientID, u.ClientID, u.LinkHash, u.TokenHash, r.Header.Get("Idempotency-Key"))
	if err != nil {
		domainError(w, err)
		return
	}
	s.kickPKI()
	http.SetCookie(w, &http.Cookie{Name: shareCookieName, Value: "", Path: s.cfg.BasePath + "/api/share/", HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	jsonResponse(w, 202, map[string]string{"status": "revocation_requested"})
}

func (s *Server) saveClientLink(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Replace bool `json:"replace"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	token, err := randomToken()
	if err != nil {
		internalError(w, "generate client link", err)
		return
	}
	s.store.LinkMu.Lock()
	defer s.store.LinkMu.Unlock()
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, "begin client link", err)
		return
	}
	defer tx.Rollback()
	clientID := r.PathValue("id")
	var name string
	err = tx.QueryRowContext(r.Context(), `SELECT name FROM clients WHERE id=? AND deleted_at IS NULL AND disabled=0 AND NOT EXISTS(SELECT 1 FROM operations WHERE client_id=clients.id AND kind IN ('delete_client','revoke_client') AND state IN ('pending','running','partial'))`, clientID).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		apiError(w, 409, "Client is unavailable or has an unfinished access operation")
		return
	}
	if err != nil {
		internalError(w, "load link client", err)
		return
	}
	var exists bool
	if err := tx.QueryRowContext(r.Context(), "SELECT EXISTS(SELECT 1 FROM client_links WHERE client_id=?)", clientID).Scan(&exists); err != nil {
		internalError(w, "check client link", err)
		return
	}
	if exists != input.Replace {
		apiError(w, 409, "Client link state changed; reload the client")
		return
	}
	if _, err := tx.ExecContext(r.Context(), "DELETE FROM client_link_sessions WHERE client_id=?", clientID); err != nil {
		internalError(w, "revoke client sessions", err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `INSERT INTO client_links(client_id,token_hash,created_at) VALUES (?,?,?) ON CONFLICT(client_id) DO UPDATE SET token_hash=excluded.token_hash,created_at=excluded.created_at`, clientID, tokenHash(token), time.Now().Unix()); err != nil {
		internalError(w, "save client link", err)
		return
	}
	action := "client.link.create"
	if input.Replace {
		action = "client.link.rotate"
	}
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO audit_events(actor,action,target,created_at) VALUES (?,?,?,?)", current(r).Username, action, clientID, time.Now().Unix()); err != nil {
		internalError(w, "audit client link", err)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w, "commit client link", err)
		return
	}
	s.invalidate("clients", "audit")
	jsonResponse(w, 200, map[string]string{"url": s.cfg.PublicURL + s.cfg.BasePath + "/profiles/#" + token})
}

func (s *Server) deleteClientLink(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !decodeBody(w, r, &input) {
		return
	}
	s.store.LinkMu.Lock()
	defer s.store.LinkMu.Unlock()
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, "begin link removal", err)
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(r.Context(), "DELETE FROM client_links WHERE client_id=?", r.PathValue("id"))
	if err != nil {
		internalError(w, "remove client link", err)
		return
	}
	count, err := result.RowsAffected()
	if err != nil {
		internalError(w, "check link removal", err)
		return
	}
	if count > 0 {
		if _, err := tx.ExecContext(r.Context(), "INSERT INTO audit_events(actor,action,target,created_at) VALUES (?,'client.link.delete',?,?)", current(r).Username, r.PathValue("id"), time.Now().Unix()); err != nil {
			internalError(w, "audit link removal", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		internalError(w, "commit link removal", err)
		return
	}
	s.invalidate("clients", "audit")
	jsonResponse(w, 200, map[string]string{"status": "link_deleted"})
}

func (s *Server) clientLinkCompromised(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !decodeBody(w, r, &input) {
		return
	}
	op, err := s.pki.ReportCompromise(r.Context(), current(r).Username, r.PathValue("id"), "", "", r.Header.Get("Idempotency-Key"))
	if err != nil {
		domainError(w, err)
		return
	}
	s.kickPKI()
	jsonResponse(w, 202, map[string]any{"operation": op})
}
func (s *Server) kickPKI() {
	select {
	case s.pkiKick <- struct{}{}:
	default:
	}
}
