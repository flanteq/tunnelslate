package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

var resources = []string{"panel-settings", "dashboard", "clients", "devices", "certificates", "operations", "settings", "audit", "connections", "admins", "statistics"}

type subscription struct {
	token   string
	wake    chan struct{}
	revoked chan struct{}
}

// Only a wake-up is queued: slow readers receive the latest revisions instead
// of an unbounded backlog. Reconnecting clients always reload visible data.
type eventHub struct {
	mu        sync.Mutex
	revisions map[string]uint64
	readers   map[*subscription]struct{}
	done      chan struct{}
	closed    bool
}

func newEventHub() *eventHub {
	h := &eventHub{revisions: map[string]uint64{}, readers: map[*subscription]struct{}{}, done: make(chan struct{})}
	for _, name := range resources {
		h.revisions[name] = 1
	}
	return h
}
func (h *eventHub) subscribe(token string) *subscription {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || len(h.readers) >= 256 {
		return nil
	}
	s := &subscription{token: token, wake: make(chan struct{}, 1), revoked: make(chan struct{}, 1)}
	h.readers[s] = struct{}{}
	return s
}
func (h *eventHub) unsubscribe(s *subscription) { h.mu.Lock(); delete(h.readers, s); h.mu.Unlock() }
func (h *eventHub) invalidate(names ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, name := range names {
		h.revisions[name]++
	}
	for reader := range h.readers {
		select {
		case reader.wake <- struct{}{}:
		default:
		}
	}
}
func (h *eventHub) snapshot() map[string]uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make(map[string]uint64, len(h.revisions))
	for name, revision := range h.revisions {
		result[name] = revision
	}
	return result
}
func (h *eventHub) revoke(token string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for reader := range h.readers {
		if token == "" || reader.token == token {
			select {
			case reader.revoked <- struct{}{}:
			default:
			}
		}
	}
}
func (s *Server) StopEvents() {
	s.events.mu.Lock()
	defer s.events.mu.Unlock()
	if !s.events.closed {
		s.events.closed = true
		close(s.events.done)
	}
}
func (s *Server) invalidate(names ...string) {
	for _, name := range names {
		if name == "clients" || name == "devices" {
			names = append(names, "statistics")
			break
		}
	}
	s.events.invalidate(names...)
	for _, name := range names {
		if name == "connections" {
			select {
			case s.liveKick <- struct{}{}:
			default:
			}
			break
		}
	}
}
func (s *Server) streamSessionValid(r *http.Request) (bool, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var exists bool
	err := s.store.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND expires_at>?)", current(r).TokenHash, time.Now().Unix()).Scan(&exists)
	return exists, err
}

func (s *Server) streamEvents(w http.ResponseWriter, r *http.Request) {
	if !s.validOrigin(r) {
		apiError(w, 403, "Origin not allowed")
		return
	}
	reader := s.events.subscribe(current(r).TokenHash)
	if reader == nil {
		apiError(w, 503, "Event stream is unavailable; retry later")
		return
	}
	defer s.events.unsubscribe(reader)
	controller := http.NewResponseController(w)
	// Override the ordinary response timeout only for this streaming response.
	_ = controller.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	write := func(event string, data any) bool {
		body, err := json.Marshal(data)
		if err != nil {
			return false
		}
		_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, body)
		if err == nil {
			err = controller.Flush()
		}
		_ = controller.SetWriteDeadline(time.Time{})
		return err == nil
	}
	validate := func() bool {
		valid, err := s.streamSessionValid(r)
		// A temporary database error reconnects the stream; it does not log out
		// a valid administrator as though the session had been revoked.
		if err != nil {
			return false
		}
		if !valid {
			write("session-expired", struct{}{})
			return false
		}
		return true
	}
	send := func(event string) bool {
		if !validate() {
			return false
		}
		live := s.getLive(r.Context(), false)
		return write(event, map[string]any{"revisions": s.events.snapshot(), "vpn": live.VPN, "crl": live.CRL, "applied_revision": live.AppliedRevision})
	}
	if !send("ready") {
		return
	}
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.events.done:
			return
		case <-reader.revoked:
			write("session-expired", struct{}{})
			return
		case <-reader.wake:
			if !send("state") {
				return
			}
		case <-heartbeat.C:
			if !validate() {
				return
			}
			if !write("heartbeat", struct{}{}) {
				return
			}
		}
	}
}
