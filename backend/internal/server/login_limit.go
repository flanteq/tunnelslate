package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"
)

const loginFailureWindow = 15 * time.Minute
const loginBanDuration = 15 * time.Minute
const loginFailureLimit = 5

type loginBanError struct{ until int64 }

func (e *loginBanError) Error() string { return "Sign-in temporarily blocked for this IP" }

func (s *Server) loginNow() time.Time {
	if s.loginClock != nil {
		return s.loginClock()
	}
	return time.Now()
}

// Unknown peers share a bucket rather than bypassing protection. Real HTTP
// connections always have an IP; forwarding headers require a trusted proxy.
func (s *Server) loginIP(r *http.Request) string {
	if ip := s.loginAddress(r); ip != "" {
		return ip
	}
	return "unknown"
}

type loginQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Server) loginBan(r *http.Request, q loginQuery) error {
	var until int64
	err := q.QueryRowContext(r.Context(), "SELECT blocked_until FROM login_ip_bans WHERE ip=? AND blocked_until>?", s.loginIP(r), s.loginNow().Unix()).Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return &loginBanError{until: until}
}

func (s *Server) respondLoginBan(w http.ResponseWriter, err error) bool {
	var ban *loginBanError
	if !errors.As(err, &ban) {
		return false
	}
	seconds := max(int64(1), ban.until-s.loginNow().Unix())
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	jsonResponse(w, http.StatusTooManyRequests, map[string]any{
		"code": "auth.ip_blocked", "error": ban.Error(),
		"params": map[string]any{"retry_after": seconds, "retry_at": ban.until},
	})
	return true
}

func (s *Server) loginIPAllowed(w http.ResponseWriter, r *http.Request, q loginQuery) bool {
	if err := s.loginBan(r, q); err != nil {
		if !s.respondLoginBan(w, err) {
			internalError(w, "check sign-in IP limit", err)
		}
		return false
	}
	return true
}

// Called inside the same transaction as the failure and its audit event. Once
// banned, further requests cannot extend the ban or create duplicate events.
func (s *Server) recordLoginFailure(r *http.Request, tx *sql.Tx) (until int64, newlyBanned bool, err error) {
	if err = s.loginBan(r, tx); err != nil {
		var ban *loginBanError
		if errors.As(err, &ban) {
			return ban.until, false, nil
		}
		return 0, false, err
	}
	ip, now := s.loginIP(r), s.loginNow().Unix()
	cutoff := now - int64(loginFailureWindow/time.Second)
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM login_ip_failures WHERE ip=? AND failed_at<=?", ip, cutoff); err != nil {
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO login_ip_failures(ip,failed_at) VALUES (?,?)", ip, now); err != nil {
		return
	}
	var count int
	if err = tx.QueryRowContext(r.Context(), "SELECT count(*) FROM login_ip_failures WHERE ip=?", ip).Scan(&count); err != nil || count < loginFailureLimit {
		return
	}
	until = now + int64(loginBanDuration/time.Second)
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO login_ip_bans(ip,blocked_until) VALUES (?,?)
 ON CONFLICT(ip) DO UPDATE SET blocked_until=excluded.blocked_until`, ip, until); err != nil {
		return
	}
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM login_ip_failures WHERE ip=?", ip); err != nil {
		return
	}
	_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_events(actor,action,target,severity,created_at)
 VALUES ('system','auth.ip_blocked',?,'WARNING',?)`, ip, now)
	newlyBanned = err == nil
	return
}

func (s *Server) rejectLogin(w http.ResponseWriter, r *http.Request) {
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		internalError(w, "begin failed sign-in", err)
		return
	}
	defer tx.Rollback()
	until, banned, err := s.recordLoginFailure(r, tx)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		internalError(w, "save failed sign-in", err)
		return
	}
	if banned {
		s.invalidate("audit")
	}
	if until > 0 {
		s.respondLoginBan(w, &loginBanError{until: until})
		return
	}
	apiError(w, 401, "Invalid username or password")
}
