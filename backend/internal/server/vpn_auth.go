package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"tunnelslate/internal/vpnauth"
)

func (s *Server) StartVPNAuth(ctx context.Context) error { return s.vpnAuth.Start(ctx) }
func (s *Server) runVPNAuth(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		work, cancel := context.WithTimeout(ctx, 8*time.Second)
		if err := s.vpnAuth.ProcessDisconnects(work); err != nil && ctx.Err() == nil {
			slog.Warn("VPN authentication policy disconnect pending")
		}
		if err := s.vpnAuth.Publish(work); err != nil && ctx.Err() == nil {
			slog.Warn("VPN authentication policy publication pending")
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func vpnAuthError(w http.ResponseWriter, err error) {
	var expected *vpnauth.Error
	if errors.As(err, &expected) {
		jsonResponse(w, expected.Status, map[string]string{"error": "VPN authentication request rejected", "code": expected.Code})
		return
	}
	internalError(w, "VPN authentication configuration", err)
}
func (s *Server) authProviders(w http.ResponseWriter, r *http.Request) {
	result, err := s.vpnAuth.Providers(r.Context())
	if err != nil {
		vpnAuthError(w, err)
		return
	}
	jsonResponse(w, 200, result)
}
func (s *Server) saveAuthProvider(w http.ResponseWriter, r *http.Request) {
	var p vpnauth.Provider
	if !decodeBody(w, r, &p) {
		return
	}
	p.ID = r.PathValue("id")
	result, err := s.vpnAuth.SaveProvider(r.Context(), p, current(r).Username)
	if err != nil {
		vpnAuthError(w, err)
		return
	}
	jsonResponse(w, 200, result)
}
func (s *Server) deleteAuthProvider(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Revision int64 `json:"revision"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if err := s.vpnAuth.DeleteProvider(r.Context(), r.PathValue("id"), input.Revision, current(r).Username); err != nil {
		vpnAuthError(w, err)
		return
	}
	jsonResponse(w, 200, map[string]string{"status": "ok"})
}
func (s *Server) testAuthProvider(w http.ResponseWriter, r *http.Request) {
	if !s.allowAttempt("vpn-provider-test:"+s.loginIP(r), 10) {
		apiError(w, 429, "Too many login attempts; try again later")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if err := s.vpnAuth.Test(r.Context(), r.PathValue("id"), input.Username, input.Password); err != nil {
		vpnAuthError(w, err)
		return
	}
	jsonResponse(w, 200, map[string]string{"status": "ok"})
}
func (s *Server) authBinding(save bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if save {
			var input vpnauth.Binding
			if !decodeBody(w, r, &input) {
				return
			}
			result, err := s.vpnAuth.SaveBinding(r.Context(), r.PathValue("id"), input, current(r).Username)
			if err != nil {
				vpnAuthError(w, err)
				return
			}
			jsonResponse(w, 200, result)
			return
		}
		result, err := s.vpnAuth.Binding(r.Context(), r.PathValue("id"))
		if err != nil {
			vpnAuthError(w, err)
			return
		}
		jsonResponse(w, 200, result)
	}
}
