package server

import (
	"database/sql"
	"errors"
	"net/http"
	"time"
)

var errLoginChanged = errors.New("login credentials changed")

type loginIdentity struct {
	ID                                     int64
	Username, PasswordHash, TOTPGeneration string
	SetupRequired                          bool
}

type loginResult struct {
	ID            int64  `json:"id"`
	Username      string `json:"username"`
	CSRF          string `json:"csrf_token"`
	SetupRequired bool   `json:"password_setup_required"`
	cookie        *http.Cookie
}

// Both password-only and TOTP logins create the session in the same transaction
// that rechecks their credentials. Enabling TOTP cannot race a password-only login.
func (s *Server) newLoginSession(r *http.Request, tx *sql.Tx, identity loginIdentity) (loginResult, error) {
	if err := s.loginBan(r, tx); err != nil {
		return loginResult{}, err
	}
	token, err := randomToken()
	if err != nil {
		return loginResult{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return loginResult{}, err
	}
	now := time.Now()
	expires := now.Add(s.cfg.SessionTTL)
	if _, err := tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE expires_at<=?", now.Unix()); err != nil {
		return loginResult{}, err
	}
	result, err := tx.ExecContext(r.Context(), `INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at,created_at,ip_address)
 SELECT ?,a.id,?,?,?,? FROM admins a WHERE a.id=? AND a.username=? AND a.password_hash=?
 AND ((?='' AND NOT EXISTS(SELECT 1 FROM admin_totp t WHERE t.admin_id=a.id))
 OR EXISTS(SELECT 1 FROM admin_totp t WHERE t.admin_id=a.id AND t.generation=?))`,
		tokenHash(token), csrf, expires.Unix(), now.Unix(), s.loginAddress(r), identity.ID, identity.Username, identity.PasswordHash, identity.TOTPGeneration, identity.TOTPGeneration)
	if err != nil {
		return loginResult{}, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return loginResult{}, err
	}
	if count != 1 {
		return loginResult{}, errLoginChanged
	}
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO audit_events(actor,action,created_at) VALUES (?,'auth.login',?)", identity.Username, now.Unix()); err != nil {
		return loginResult{}, err
	}
	return loginResult{ID: identity.ID, Username: identity.Username, CSRF: csrf, SetupRequired: identity.SetupRequired, cookie: &http.Cookie{
		Name: cookieName, Value: token, Path: s.cfg.BasePath + "/", HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
		Expires: expires, MaxAge: int(s.cfg.SessionTTL.Seconds()),
	}}, nil
}

func (s *Server) respondLogin(w http.ResponseWriter, result loginResult) {
	s.invalidate("audit", "admins")
	http.SetCookie(w, result.cookie)
	jsonResponse(w, 200, result)
}
