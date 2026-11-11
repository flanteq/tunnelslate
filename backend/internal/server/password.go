package server

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"
	"unicode/utf8"

	"tunnelslate/internal/passwordhash"
)

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	s.savePassword(w, r, false)
}

func (s *Server) setupPassword(w http.ResponseWriter, r *http.Request) {
	if !current(r).PasswordSetupRequired {
		apiError(w, 409, "Administrator password has already been set")
		return
	}
	s.savePassword(w, r, true)
}

func (s *Server) savePassword(w http.ResponseWriter, r *http.Request, initial bool) {
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	// The setup endpoint intentionally accepts no current password at all.
	if initial {
		var setup struct {
			NewPassword string `json:"new_password"`
		}
		if !decodeBody(w, r, &setup) {
			return
		}
		input.NewPassword = setup.NewPassword
	} else if !decodeBody(w, r, &input) {
		return
	}
	if !passwordhash.ValidNew(input.NewPassword) {
		apiError(w, 400, "New password must be 12–72 characters")
		return
	}
	if !initial && (len(input.CurrentPassword) == 0 || utf8.RuneCountInString(input.CurrentPassword) > 72) {
		apiError(w, 400, "Current password must be 1–72 characters")
		return
	}
	u := current(r)
	key := "password:" + u.Username
	if !s.allowAttempt(key, 5) {
		w.Header().Set("Retry-After", "300")
		apiError(w, 429, "Too many password change attempts; try again later")
		return
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		apiError(w, 429, "Authentication is busy; try again later")
		return
	}
	var previousHash string
	err := s.store.DB.QueryRowContext(r.Context(), "SELECT password_hash FROM admins WHERE id=? AND username=?", u.AdminID, u.Username).Scan(&previousHash)
	if errors.Is(err, sql.ErrNoRows) {
		apiError(w, 401, "Session expired; sign in again")
		return
	}
	if err != nil {
		internalError(w, "load password hash", err)
		return
	}
	if !initial && passwordhash.Verify(previousHash, input.CurrentPassword) != nil {
		apiError(w, 403, "Current password is incorrect")
		return
	}
	if (initial && passwordhash.Verify(previousHash, input.NewPassword) == nil) || (!initial && input.NewPassword == input.CurrentPassword) {
		apiError(w, 400, "New password must differ from current password")
		return
	}
	encoded, err := passwordhash.Hash(input.NewPassword)
	if err != nil {
		internalError(w, "hash new password", err)
		return
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, "begin password change", err)
		return
	}
	defer tx.Rollback()
	// Recheck the session and previous hash in the same transaction as the
	// update: a revoked session/concurrent password change cannot overwrite it.
	result, err := tx.ExecContext(r.Context(), `UPDATE admins SET password_hash=?,password_setup_required=0,bootstrap_pending=0
	 WHERE id=? AND username=? AND password_hash=? AND password_setup_required=?
	 AND EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND admin_id=? AND expires_at>?)`,
		encoded, u.AdminID, u.Username, previousHash, initial, u.TokenHash, u.AdminID, time.Now().Unix())
	if err != nil {
		internalError(w, "update password hash", err)
		return
	}
	affected, err := result.RowsAffected()
	if err != nil {
		internalError(w, "check password update", err)
		return
	}
	if affected != 1 {
		apiError(w, 401, "Session expired; sign in again")
		return
	}
	tokens, err := adminSessionTokens(r.Context(), tx, u.AdminID)
	if err != nil {
		internalError(w, "load administrator sessions", err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE admin_id=?", u.AdminID); err != nil {
		internalError(w, "revoke administrator sessions", err)
		return
	}
	action := "auth.password.change"
	if initial {
		action = "auth.password.setup"
	}
	if _, err := tx.ExecContext(r.Context(), "INSERT INTO audit_events(actor,action,created_at) VALUES (?,?,?)", u.Username, action, time.Now().Unix()); err != nil {
		internalError(w, "audit password change", err)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w, "commit password change", err)
		return
	}
	// The credential change is committed even if file cleanup needs a retry.
	// Use a separate context: disconnecting the browser cannot interrupt cleanup.
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.store.CleanupInitialPassword(cleanup); err != nil {
		slog.Warn("Initial password file cleanup pending", "error", err)
	}
	for _, token := range tokens {
		s.events.revoke(token)
	}
	s.invalidate("audit", "admins")
	s.loginMu.Lock()
	delete(s.attempts, key)
	s.loginMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: s.cfg.BasePath + "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
	jsonResponse(w, 200, map[string]string{"status": "password_changed"})
}
