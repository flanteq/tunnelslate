package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"image/png"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"tunnelslate/internal/branding"
	"unicode/utf8"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"

	"tunnelslate/internal/passwordhash"
)

const totpAttemptWindow = 5 * time.Minute

func (s *Server) totpNow() time.Time {
	if s.totpClock != nil {
		return s.totpClock()
	}
	return time.Now()
}

func (s *Server) beginTOTPLogin(w http.ResponseWriter, r *http.Request, identity loginIdentity) {
	token, err := randomToken()
	if err != nil {
		internalError(w, "generate TOTP challenge", err)
		return
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, "begin TOTP challenge", err)
		return
	}
	defer tx.Rollback()
	if !s.loginIPAllowed(w, r, tx) {
		return
	}
	now := s.totpNow().Unix()
	if !s.totpAttemptAllowed(w, r, tx, identity.ID, now) {
		return
	}
	// Bound unfinished challenges per account, including simultaneous logins.
	if _, err = tx.ExecContext(r.Context(), `DELETE FROM admin_login_challenges WHERE expires_at<=?
 OR (admin_id=? AND token_hash IN (SELECT token_hash FROM admin_login_challenges WHERE admin_id=? ORDER BY expires_at DESC,rowid DESC LIMIT -1 OFFSET 4))`, now, identity.ID, identity.ID); err != nil {
		internalError(w, "prune TOTP challenges", err)
		return
	}
	expires := now + int64(totpAttemptWindow/time.Second)
	result, err := tx.ExecContext(r.Context(), `INSERT INTO admin_login_challenges(token_hash,admin_id,password_hash,generation,expires_at)
 SELECT ?,a.id,a.password_hash,t.generation,? FROM admins a JOIN admin_totp t ON t.admin_id=a.id
 WHERE a.id=? AND a.username=? AND a.password_hash=? AND t.generation=?`, tokenHash(token), expires, identity.ID, identity.Username, identity.PasswordHash, identity.TOTPGeneration)
	if err != nil {
		internalError(w, "save TOTP challenge", err)
		return
	}
	count, err := result.RowsAffected()
	if err != nil {
		internalError(w, "check TOTP challenge", err)
		return
	}
	if count != 1 {
		apiError(w, 401, "Invalid username or password")
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w, "commit TOTP challenge", err)
		return
	}
	jsonResponse(w, 202, map[string]any{"totp_required": true, "challenge_token": token, "expires_at": expires})
}

func (s *Server) totpAttemptAllowed(w http.ResponseWriter, r *http.Request, tx *sql.Tx, id, now int64) bool {
	var attempts int
	var reset int64
	err := tx.QueryRowContext(r.Context(), "SELECT attempts,reset_at FROM admin_totp_attempts WHERE admin_id=?", id).Scan(&attempts, &reset)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		internalError(w, "read TOTP attempt limit", err)
		return false
	}
	if attempts >= 5 && reset > now {
		w.Header().Set("Retry-After", strconv.FormatInt(reset-now, 10))
		apiError(w, 429, "Too many TOTP attempts; try again later")
		return false
	}
	return true
}

func (s *Server) rejectTOTP(w http.ResponseWriter, r *http.Request, tx *sql.Tx, id, now int64, status int) {
	_, err := tx.ExecContext(r.Context(), `INSERT INTO admin_totp_attempts(admin_id,attempts,reset_at) VALUES (?,1,?)
 ON CONFLICT(admin_id) DO UPDATE SET attempts=CASE WHEN reset_at<=? THEN 1 ELSE attempts+1 END,
 reset_at=CASE WHEN reset_at<=? THEN excluded.reset_at ELSE reset_at END`, id, now+int64(totpAttemptWindow/time.Second), now, now)
	var until int64
	var banned bool
	if err == nil && status == http.StatusUnauthorized {
		until, banned, err = s.recordLoginFailure(r, tx)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		internalError(w, "save failed TOTP attempt", err)
		return
	}
	if banned {
		s.invalidate("audit")
	}
	if until > 0 {
		s.respondLoginBan(w, &loginBanError{until: until})
		return
	}
	apiError(w, status, "Invalid or already used TOTP code")
}

// Return the matched counter so accepting a code also consumes it atomically.
// A single adjacent step in either direction covers modest clock skew.
func matchTOTPStep(secret, code string, now time.Time, last int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	step := now.Unix() / 30
	for _, offset := range []int64{0, -1, 1} {
		counter := step + offset
		if counter <= last || counter < 0 {
			continue
		}
		valid, err := hotp.ValidateCustom(code, uint64(counter), secret, hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && valid {
			return counter, true
		}
	}
	return 0, false
}

func (s *Server) completeTOTPLogin(w http.ResponseWriter, r *http.Request) {
	if !s.validOrigin(r) {
		apiError(w, 403, "Origin not allowed")
		return
	}
	if !s.loginIPAllowed(w, r, s.store.DB) {
		return
	}
	if !s.allowLogin(r) {
		w.Header().Set("Retry-After", "300")
		apiError(w, 429, "Too many TOTP attempts; try again later")
		return
	}

	var input struct {
		Challenge string `json:"challenge_token"`
		Code      string `json:"code"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if len(input.Challenge) != 64 {
		apiError(w, 401, "TOTP sign-in expired; enter your password again")
		return
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, "begin TOTP sign-in", err)
		return
	}
	defer tx.Rollback()
	if !s.loginIPAllowed(w, r, tx) {
		return
	}
	var identity loginIdentity
	var encrypted string
	var last int64
	now := s.totpNow()
	err = tx.QueryRowContext(r.Context(), `SELECT a.id,a.username,a.password_hash,a.password_setup_required,t.generation,t.secret,t.last_used_step
 FROM admin_login_challenges c JOIN admins a ON a.id=c.admin_id JOIN admin_totp t ON t.admin_id=a.id
 WHERE c.token_hash=? AND c.expires_at>? AND c.password_hash=a.password_hash AND c.generation=t.generation`, tokenHash(input.Challenge), now.Unix()).Scan(
		&identity.ID, &identity.Username, &identity.PasswordHash, &identity.SetupRequired, &identity.TOTPGeneration, &encrypted, &last)
	if errors.Is(err, sql.ErrNoRows) {
		apiError(w, 401, "TOTP sign-in expired; enter your password again")
		return
	}
	if err != nil {
		internalError(w, "read TOTP sign-in", err)
		return
	}
	if !s.totpAttemptAllowed(w, r, tx, identity.ID, now.Unix()) {
		return
	}
	secret, err := s.store.OpenTOTPSecret(identity.ID, encrypted)
	if err != nil {
		internalError(w, "decrypt TOTP sign-in secret", err)
		return
	}
	step, valid := matchTOTPStep(secret, input.Code, now, last)
	if !valid {
		s.rejectTOTP(w, r, tx, identity.ID, now.Unix(), 401)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "UPDATE admin_totp SET last_used_step=? WHERE admin_id=?", step, identity.ID); err != nil {
		internalError(w, "consume TOTP code", err)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM admin_login_challenges WHERE token_hash=?", tokenHash(input.Challenge)); err != nil {
		internalError(w, "consume TOTP challenge", err)
		return
	}
	result, err := s.newLoginSession(r, tx, identity)
	if s.respondLoginBan(w, err) {
		return
	}
	if errors.Is(err, errLoginChanged) {
		apiError(w, 401, "TOTP sign-in expired; enter your password again")
		return
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		internalError(w, "commit TOTP sign-in", err)
		return
	}
	s.respondLogin(w, result)
}

func (s *Server) verifyTOTPPassword(w http.ResponseWriter, r *http.Request, password string) (string, bool) {
	u := current(r)
	if !s.allowAttempt("totp-settings:"+strconv.FormatInt(u.AdminID, 10), 5) {
		w.Header().Set("Retry-After", "300")
		apiError(w, 429, "Too many TOTP attempts; try again later")
		return "", false
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		apiError(w, 429, "Authentication is busy; try again later")
		return "", false
	}
	var hash string
	err := s.store.DB.QueryRowContext(r.Context(), "SELECT password_hash FROM admins WHERE id=?", u.AdminID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		apiError(w, 401, "Session expired; sign in again")
		return "", false
	}
	if err != nil {
		internalError(w, "read TOTP settings password", err)
		return "", false
	}
	if utf8.RuneCountInString(password) > 72 || passwordhash.Verify(hash, password) != nil {
		apiError(w, 403, "Current password is incorrect")
		return "", false
	}
	return hash, true
}

func (s *Server) newTOTPKey(username string) (*otp.Key, error) {
	origin, _ := url.Parse(s.cfg.PublicURL)
	// Authenticator labels reserve ':' for the issuer/account separator. Keep
	// ports, IPv6 and subpaths identifiable without adding label separators.
	account := username + "@" + strings.ReplaceAll(origin.Hostname(), ":", "-")
	if port := origin.Port(); port != "" {
		account += " (" + port + ")"
	}
	if s.cfg.BasePath != "" {
		account += " [" + strings.ReplaceAll(strings.TrimPrefix(s.cfg.BasePath, "/"), "/", "-") + "]"
	}
	return totp.Generate(totp.GenerateOpts{Issuer: branding.Name, AccountName: account, SecretSize: 32})
}

func (s *Server) startTOTPSetup(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Password string `json:"current_password"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	hash, ok := s.verifyTOTPPassword(w, r, input.Password)
	if !ok {
		return
	}
	u := current(r)
	key, err := s.newTOTPKey(u.Username)
	if err != nil {
		internalError(w, "generate TOTP setup", err)
		return
	}
	qr, err := key.Image(256, 256)
	if err != nil {
		internalError(w, "generate TOTP QR code", err)
		return
	}
	var image bytes.Buffer
	if err := png.Encode(&image, qr); err != nil {
		internalError(w, "encode TOTP QR code", err)
		return
	}
	encrypted, err := s.store.SealTOTPSecret(r.Context(), u.AdminID, key.Secret())
	if err != nil {
		internalError(w, "encrypt TOTP setup", err)
		return
	}
	setup, err := randomToken()
	if err != nil {
		internalError(w, "generate TOTP setup token", err)
		return
	}
	tx, ok := s.beginAdminMutation(w, r)
	if !ok {
		return
	}
	defer tx.Rollback()
	var enabled bool
	if err := tx.QueryRowContext(r.Context(), "SELECT EXISTS(SELECT 1 FROM admin_totp WHERE admin_id=?)", u.AdminID).Scan(&enabled); err != nil {
		internalError(w, "read TOTP state", err)
		return
	}
	if enabled {
		apiError(w, 409, "TOTP is already enabled")
		return
	}
	expires := s.totpNow().Add(10 * time.Minute).Unix()
	_, err = tx.ExecContext(r.Context(), `INSERT INTO admin_totp_setups(admin_id,session_hash,setup_hash,password_hash,secret,expires_at)
 VALUES (?,?,?,?,?,?) ON CONFLICT(admin_id) DO UPDATE SET session_hash=excluded.session_hash,setup_hash=excluded.setup_hash,
 password_hash=excluded.password_hash,secret=excluded.secret,expires_at=excluded.expires_at`, u.AdminID, u.TokenHash, tokenHash(setup), hash, encrypted, expires)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		internalError(w, "save TOTP setup", err)
		return
	}
	jsonResponse(w, 200, map[string]any{"setup_token": setup, "secret": key.Secret(), "qr_code": "data:image/png;base64," + base64.StdEncoding.EncodeToString(image.Bytes()), "expires_at": expires})
}

func (s *Server) enableTOTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Setup string `json:"setup_token"`
		Code  string `json:"code"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if len(input.Setup) != 64 {
		apiError(w, 409, "TOTP setup expired; start again")
		return
	}
	tx, ok := s.beginAdminMutation(w, r)
	if !ok {
		return
	}
	defer tx.Rollback()
	u := current(r)
	now := s.totpNow()
	var encrypted string
	err := tx.QueryRowContext(r.Context(), `SELECT p.secret FROM admin_totp_setups p JOIN admins a ON a.id=p.admin_id
 WHERE p.admin_id=? AND p.session_hash=? AND p.setup_hash=? AND p.expires_at>? AND p.password_hash=a.password_hash
 AND NOT EXISTS(SELECT 1 FROM admin_totp t WHERE t.admin_id=p.admin_id)`, u.AdminID, u.TokenHash, tokenHash(input.Setup), now.Unix()).Scan(&encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		apiError(w, 409, "TOTP setup expired; start again")
		return
	}
	if err != nil {
		internalError(w, "read TOTP setup", err)
		return
	}
	if !s.totpAttemptAllowed(w, r, tx, u.AdminID, now.Unix()) {
		return
	}
	secret, err := s.store.OpenTOTPSecret(u.AdminID, encrypted)
	if err != nil {
		internalError(w, "decrypt TOTP setup", err)
		return
	}
	step, valid := matchTOTPStep(secret, input.Code, now, -1)
	if !valid {
		s.rejectTOTP(w, r, tx, u.AdminID, now.Unix(), 400)
		return
	}
	generation, err := randomToken()
	if err != nil {
		internalError(w, "generate TOTP generation", err)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO admin_totp(admin_id,secret,generation,last_used_step) VALUES (?,?,?,?)", u.AdminID, encrypted, generation, step); err != nil {
		internalError(w, "enable TOTP", err)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM admin_totp_setups WHERE admin_id=?", u.AdminID); err != nil {
		internalError(w, "remove TOTP setup", err)
		return
	}
	tokens, err := s.endOtherTOTPSessions(r.Context(), tx, u)
	if err != nil {
		internalError(w, "end sessions after enabling TOTP", err)
		return
	}
	if err := auditAdmin(r.Context(), tx, u.Username, "auth.totp.enabled", u.Username); err != nil {
		internalError(w, "audit TOTP enable", err)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w, "commit TOTP enable", err)
		return
	}
	s.adminChanged(tokens)
	jsonResponse(w, 200, map[string]bool{"totp_enabled": true})
}

func (s *Server) endOtherTOTPSessions(ctx context.Context, tx *sql.Tx, u session) ([]string, error) {
	tokens, err := adminSessionTokens(ctx, tx, u.AdminID)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE admin_id=? AND token_hash!=?", u.AdminID, u.TokenHash); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM admin_login_challenges WHERE admin_id=?", u.AdminID); err != nil {
		return nil, err
	}
	others := []string{}
	for _, token := range tokens {
		if token != u.TokenHash {
			others = append(others, token)
		}
	}
	return others, nil
}

func (s *Server) disableTOTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Password string `json:"current_password"`
		Code     string `json:"code"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if _, ok := s.verifyTOTPPassword(w, r, input.Password); !ok {
		return
	}
	tx, ok := s.beginAdminMutation(w, r)
	if !ok {
		return
	}
	defer tx.Rollback()
	u := current(r)
	now := s.totpNow()
	var encrypted string
	var last int64
	err := tx.QueryRowContext(r.Context(), "SELECT secret,last_used_step FROM admin_totp WHERE admin_id=?", u.AdminID).Scan(&encrypted, &last)
	if errors.Is(err, sql.ErrNoRows) {
		apiError(w, 409, "TOTP is not enabled")
		return
	}
	if err != nil {
		internalError(w, "read TOTP disable state", err)
		return
	}
	if !s.totpAttemptAllowed(w, r, tx, u.AdminID, now.Unix()) {
		return
	}
	secret, err := s.store.OpenTOTPSecret(u.AdminID, encrypted)
	if err != nil {
		internalError(w, "decrypt TOTP disable secret", err)
		return
	}
	if _, valid := matchTOTPStep(secret, input.Code, now, last); !valid {
		s.rejectTOTP(w, r, tx, u.AdminID, now.Unix(), 400)
		return
	}
	if _, err := tx.ExecContext(r.Context(), "DELETE FROM admin_totp WHERE admin_id=?", u.AdminID); err != nil {
		internalError(w, "disable TOTP", err)
		return
	}
	tokens, err := s.endOtherTOTPSessions(r.Context(), tx, u)
	if err != nil {
		internalError(w, "end sessions after disabling TOTP", err)
		return
	}
	if err := auditAdmin(r.Context(), tx, u.Username, "auth.totp.disabled", u.Username); err != nil {
		internalError(w, "audit TOTP disable", err)
		return
	}
	if err := tx.Commit(); err != nil {
		internalError(w, "commit TOTP disable", err)
		return
	}
	s.adminChanged(tokens)
	jsonResponse(w, 200, map[string]bool{"totp_enabled": false})
}
