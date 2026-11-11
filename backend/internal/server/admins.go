package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	"tunnelslate/internal/passwordhash"
	"tunnelslate/internal/store"
)

type adminAccount struct {
	ID             int64          `json:"id"`
	Username       string         `json:"username"`
	CreatedAt      int64          `json:"created_at"`
	SetupRequired  bool           `json:"password_setup_required"`
	TOTPEnabled    bool           `json:"totp_enabled"`
	Current        bool           `json:"current"`
	Sessions       int            `json:"sessions"`
	SessionDetails []adminSession `json:"session_details"`
}

func accountName(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body struct {
		Username string `json:"username"`
	}
	if !decodeBody(w, r, &body) {
		return "", false
	}
	name, err := store.NormalizeAdminUsername(body.Username)
	if errors.Is(err, store.ErrAdminUsernameReserved) {
		apiError(w, 400, "Имя system зарезервировано для системных событий")
		return "", false
	}
	if err != nil {
		apiError(w, 400, "Имя: 3–64 символа, латинские буквы, цифры, точка, дефис и подчёркивание")
		return "", false
	}
	return name, true
}

type adminSession struct {
	IPAddress string `json:"ip_address"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	Current   bool   `json:"current"`
}

func (s *Server) listAdmins(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT a.id,a.username,a.created_at,a.password_setup_required,EXISTS(SELECT 1 FROM admin_totp t WHERE t.admin_id=a.id),p.ip_address,p.created_at,p.expires_at,p.token_hash=?
 FROM admins a LEFT JOIN sessions p ON p.admin_id=a.id AND p.expires_at>?
 ORDER BY (a.id=?) DESC,a.username COLLATE NOCASE,p.created_at DESC,p.rowid DESC`, current(r).TokenHash, time.Now().Unix(), current(r).AdminID)
	if err != nil {
		internalError(w, "list administrators", err)
		return
	}
	defer rows.Close()
	result := []adminAccount{}
	for rows.Next() {
		var a adminAccount
		var ip sql.NullString
		var created, expires sql.NullInt64
		var own sql.NullBool
		if err := rows.Scan(&a.ID, &a.Username, &a.CreatedAt, &a.SetupRequired, &a.TOTPEnabled, &ip, &created, &expires, &own); err != nil {
			internalError(w, "read administrator", err)
			return
		}
		if len(result) == 0 || result[len(result)-1].ID != a.ID {
			a.Current = a.ID == current(r).AdminID
			a.SessionDetails = []adminSession{}
			result = append(result, a)
		}
		account := &result[len(result)-1]
		if expires.Valid {
			account.SessionDetails = append(account.SessionDetails, adminSession{IPAddress: ip.String, CreatedAt: created.Int64, ExpiresAt: expires.Int64, Current: own.Bool})
			account.Sessions++
		}
	}
	if err := rows.Err(); err != nil {
		internalError(w, "list administrators", err)
		return
	}
	jsonResponse(w, 200, result)
}
func (s *Server) endAdminSessions(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !decodeBody(w, r, &input) {
		return
	}
	tx, ok := s.beginAdminMutation(w, r)
	if !ok {
		return
	}
	defer tx.Rollback()
	a, ok := targetAdmin(w, r, tx)
	if !ok {
		return
	}
	tokens, err := adminSessionTokens(r.Context(), tx, a.ID)
	if err != nil {
		internalError(w, "load administrator sessions", err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE admin_id=?", a.ID); err != nil {
		internalError(w, "end administrator sessions", err)
		return
	}
	if err := auditAdmin(r.Context(), tx, current(r).Username, "admin.sessions.end", a.Username); err != nil {
		internalError(w, "audit administrator sessions termination", err)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w, "commit administrator sessions termination", err)
		return
	}
	s.adminChanged(tokens)
	own := a.ID == current(r).AdminID
	if own {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: s.cfg.BasePath + "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
	}
	jsonResponse(w, 200, map[string]any{"status": "sessions_ended", "username": a.Username, "signed_out": own})
}

func (s *Server) expireAdminSessions(ctx context.Context) error {
	result, err := s.store.DB.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<=?", time.Now().Unix())
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err == nil && count > 0 {
		s.events.invalidate("admins")
	}
	for _, query := range []string{
		"DELETE FROM admin_login_challenges WHERE expires_at<=?",
		"DELETE FROM admin_totp_setups WHERE expires_at<=?",
		"DELETE FROM admin_totp_attempts WHERE reset_at<=?",
	} {
		if _, err := s.store.DB.ExecContext(ctx, query, time.Now().Unix()); err != nil {
			return err
		}
	}
	if _, err := s.store.DB.ExecContext(ctx, "DELETE FROM login_ip_failures WHERE failed_at<=?", s.loginNow().Add(-loginFailureWindow).Unix()); err != nil {
		return err
	}
	if _, err := s.store.DB.ExecContext(ctx, "DELETE FROM login_ip_bans WHERE blocked_until<=?", s.loginNow().Unix()); err != nil {
		return err
	}
	return nil
}

func adminSessionTokens(ctx context.Context, tx *sql.Tx, id int64) ([]string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT token_hash FROM sessions WHERE admin_id=?", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tokens := []string{}
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}
func (s *Server) beginAdminMutation(w http.ResponseWriter, r *http.Request) (*sql.Tx, bool) {
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, "begin administrator change", err)
		return nil, false
	}
	u := current(r)
	var valid bool
	err = tx.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT 1 FROM sessions p JOIN admins a ON a.id=p.admin_id WHERE p.token_hash=? AND p.admin_id=? AND p.expires_at>? AND a.password_setup_required=0)`, u.TokenHash, u.AdminID, time.Now().Unix()).Scan(&valid)
	if err != nil {
		tx.Rollback()
		internalError(w, "recheck administrator session", err)
		return nil, false
	}
	if !valid {
		tx.Rollback()
		apiError(w, 401, "Session expired; sign in again")
		return nil, false
	}
	return tx, true
}
func targetAdmin(w http.ResponseWriter, r *http.Request, tx *sql.Tx) (adminAccount, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		apiError(w, 404, "Учётная запись не найдена")
		return adminAccount{}, false
	}
	a := adminAccount{ID: id}
	err = tx.QueryRowContext(r.Context(), "SELECT username,password_setup_required FROM admins WHERE id=?", id).Scan(&a.Username, &a.SetupRequired)
	if errors.Is(err, sql.ErrNoRows) {
		apiError(w, 404, "Учётная запись не найдена")
		return a, false
	}
	if err != nil {
		internalError(w, "load administrator", err)
		return a, false
	}
	return a, true
}
func uniqueAdminName(w http.ResponseWriter, r *http.Request, tx *sql.Tx, name string, id int64) bool {
	var exists bool
	if err := tx.QueryRowContext(r.Context(), "SELECT EXISTS(SELECT 1 FROM admins WHERE username=? AND id!=?)", name, id).Scan(&exists); err != nil {
		internalError(w, "check administrator name", err)
		return false
	}
	if exists {
		apiError(w, 409, "Администратор с таким именем уже существует")
		return false
	}
	return true
}
func auditAdmin(ctx context.Context, tx *sql.Tx, actor, action, target string) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO audit_events(actor,action,target,created_at) VALUES (?,?,?,?)", actor, action, target, time.Now().Unix())
	return err
}
func (s *Server) adminChanged(tokens []string) {
	for _, token := range tokens {
		s.events.revoke(token)
	}
	s.invalidate("admins", "audit")
}
func (s *Server) temporaryAdminPassword(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	if !s.allowAttempt("admin-credentials:"+strconv.FormatInt(current(r).AdminID, 10), 10) {
		w.Header().Set("Retry-After", "300")
		apiError(w, 429, "Слишком много операций с паролями. Повторите позднее.")
		return "", "", false
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		apiError(w, 429, "Authentication is busy; try again later")
		return "", "", false
	}
	password, err := randomToken()
	if err != nil {
		internalError(w, "generate temporary password", err)
		return "", "", false
	}
	hash, err := passwordhash.Hash(password)
	if err != nil {
		internalError(w, "hash temporary password", err)
		return "", "", false
	}
	return password, hash, true
}
func (s *Server) createAdmin(w http.ResponseWriter, r *http.Request) {
	name, ok := accountName(w, r)
	if !ok {
		return
	}
	password, hash, ok := s.temporaryAdminPassword(w, r)
	if !ok {
		return
	}
	tx, ok := s.beginAdminMutation(w, r)
	if !ok {
		return
	}
	defer tx.Rollback()
	if !uniqueAdminName(w, r, tx, name, 0) {
		return
	}
	result, err := tx.ExecContext(r.Context(), "INSERT INTO admins(username,password_hash,created_at,password_setup_required) VALUES (?,?,?,1)", name, hash, time.Now().Unix())
	if err != nil {
		internalError(w, "create administrator", err)
		return
	}
	id, err := result.LastInsertId()
	if err != nil {
		internalError(w, "read administrator ID", err)
		return
	}
	if err := auditAdmin(r.Context(), tx, current(r).Username, "admin.created", name); err != nil {
		internalError(w, "audit administrator creation", err)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w, "commit administrator creation", err)
		return
	}
	s.adminChanged(nil)
	jsonResponse(w, 201, map[string]any{"id": id, "username": name, "temporary_password": password})
}
func (s *Server) renameAdmin(w http.ResponseWriter, r *http.Request) {
	name, ok := accountName(w, r)
	if !ok {
		return
	}
	tx, ok := s.beginAdminMutation(w, r)
	if !ok {
		return
	}
	defer tx.Rollback()
	a, ok := targetAdmin(w, r, tx)
	if !ok {
		return
	}
	if !uniqueAdminName(w, r, tx, name, a.ID) {
		return
	}
	tokens := []string{}
	if name != a.Username {
		var err error
		tokens, err = adminSessionTokens(r.Context(), tx, a.ID)
		if err != nil {
			internalError(w, "load administrator sessions", err)
			return
		}
		if _, err := tx.ExecContext(r.Context(), "UPDATE admins SET username=? WHERE id=?", name, a.ID); err != nil {
			internalError(w, "rename administrator", err)
			return
		}
		if _, err := tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE admin_id=?", a.ID); err != nil {
			internalError(w, "revoke renamed administrator sessions", err)
			return
		}
		if err := auditAdmin(r.Context(), tx, current(r).Username, "admin.rename", a.Username+" → "+name); err != nil {
			internalError(w, "audit administrator rename", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		internalError(w, "commit administrator rename", err)
		return
	}
	s.adminChanged(tokens)
	jsonResponse(w, 200, map[string]any{"id": a.ID, "username": name, "signed_out": a.ID == current(r).AdminID && name != a.Username})
}
func (s *Server) resetAdminPassword(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !decodeBody(w, r, &input) {
		return
	}
	password, hash, ok := s.temporaryAdminPassword(w, r)
	if !ok {
		return
	}
	tx, ok := s.beginAdminMutation(w, r)
	if !ok {
		return
	}
	defer tx.Rollback()
	a, ok := targetAdmin(w, r, tx)
	if !ok {
		return
	}
	if a.ID == current(r).AdminID {
		apiError(w, 409, "Для собственного пароля используйте кнопку «Сменить пароль»")
		return
	}
	tokens, err := adminSessionTokens(r.Context(), tx, a.ID)
	if err != nil {
		internalError(w, "load administrator sessions", err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), "UPDATE admins SET password_hash=?,password_setup_required=1,bootstrap_pending=0 WHERE id=?", hash, a.ID); err != nil {
		internalError(w, "reset administrator password", err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE admin_id=?", a.ID); err != nil {
		internalError(w, "revoke administrator sessions", err)
		return
	}
	if err := auditAdmin(r.Context(), tx, current(r).Username, "admin.password.reset", a.Username); err != nil {
		internalError(w, "audit password reset", err)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w, "commit password reset", err)
		return
	}
	s.adminChanged(tokens)
	jsonResponse(w, 200, map[string]any{"id": a.ID, "username": a.Username, "temporary_password": password})
}
func (s *Server) deleteAdmin(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !decodeBody(w, r, &input) {
		return
	}
	tx, ok := s.beginAdminMutation(w, r)
	if !ok {
		return
	}
	defer tx.Rollback()
	a, ok := targetAdmin(w, r, tx)
	if !ok {
		return
	}
	var ready int
	if err := tx.QueryRowContext(r.Context(), "SELECT count(*) FROM admins WHERE id!=? AND password_setup_required=0", a.ID).Scan(&ready); err != nil {
		internalError(w, "check remaining administrators", err)
		return
	}
	if ready == 0 {
		apiError(w, 409, "Должен остаться хотя бы один администратор с установленным постоянным паролем. Сначала завершите настройку другой учётной записи.")
		return
	}
	tokens, err := adminSessionTokens(r.Context(), tx, a.ID)
	if err != nil {
		internalError(w, "load administrator sessions", err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), "DELETE FROM admins WHERE id=?", a.ID); err != nil {
		internalError(w, "delete administrator", err)
		return
	}
	if err := auditAdmin(r.Context(), tx, current(r).Username, "admin.delete", a.Username); err != nil {
		internalError(w, "audit administrator deletion", err)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w, "commit administrator deletion", err)
		return
	}
	s.adminChanged(tokens)
	jsonResponse(w, 200, map[string]any{"status": "deleted", "signed_out": a.ID == current(r).AdminID})
}
