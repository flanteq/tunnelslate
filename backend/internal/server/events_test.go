package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func readEvent(t *testing.T, reader *bufio.Reader) (string, map[string]json.RawMessage) {
	t.Helper()
	var name, data string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal("read event:", err)
		}
		line = strings.TrimSpace(line)
		if line == "" && name != "" {
			break
		}
		if strings.HasPrefix(line, "event: ") {
			name = strings.TrimPrefix(line, "event: ")
		}
		if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
		}
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		t.Fatal(err)
	}
	return name, payload
}

func openStream(t *testing.T, s *Server, basePath string, cookie *http.Cookie) (*bufio.Reader, *http.Response) {
	t.Helper()
	httpServer := httptest.NewUnstartedServer(s)
	httpServer.Config.WriteTimeout = 50 * time.Millisecond
	httpServer.Start()
	t.Cleanup(httpServer.Close)
	t.Cleanup(s.StopEvents)
	r, _ := http.NewRequest("GET", httpServer.URL+basePath+"/api/events", nil)
	r.AddCookie(cookie)
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	if response.StatusCode != 200 {
		t.Fatal("open stream:", response.StatusCode)
	}
	return bufio.NewReader(response.Body), response
}

func TestSSEBasePathAuthenticationAndCommittedChanges(t *testing.T) {
	_, db, cfg := fixture(t)
	cfg.BasePath = "/ovpn"
	s, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	login := request(s, "POST", "/ovpn/api/auth/login", `{"username":"admin","password":"correct-password-123"}`, nil, "", cfg.PublicURL)
	cookie := login.Result().Cookies()[0]
	var credentials struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &credentials); err != nil {
		t.Fatal(err)
	}
	if w := request(s, "GET", "/ovpn/api/events", "", nil, "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(s, "GET", "/ovpn/api/events", "", cookie, "", "https://evil.test"); w.Code != 403 {
		t.Fatal(w.Code)
	}
	reader, response := openStream(t, s, cfg.BasePath, cookie)
	if response.Header.Get("Content-Type") != "text/event-stream" || response.Header.Get("X-Accel-Buffering") != "no" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("incorrect SSE headers")
	}
	name, payload := readEvent(t, reader)
	if name != "ready" || payload["vpn"] == nil {
		t.Fatal("missing initial snapshot")
	}
	var initial map[string]uint64
	if err := json.Unmarshal(payload["revisions"], &initial); err != nil {
		t.Fatal(err)
	}
	// The ordinary response timeout has elapsed; streaming writes must still work.
	time.Sleep(100 * time.Millisecond)
	w := request(s, "POST", "/ovpn/api/clients", `{"name":"SSE client"}`, cookie, credentials.CSRF, cfg.PublicURL)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	name, payload = readEvent(t, reader)
	var changed map[string]uint64
	if err := json.Unmarshal(payload["revisions"], &changed); err != nil {
		t.Fatal(err)
	}
	if name != "state" || changed["clients"] <= initial["clients"] || changed["dashboard"] <= initial["dashboard"] {
		t.Fatal("committed change was not published")
	}
	if w := request(s, "POST", "/ovpn/api/clients", `{"name":"SSE client"}`, cookie, credentials.CSRF, cfg.PublicURL); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if s.events.snapshot()["clients"] != changed["clients"] {
		t.Fatal("rejected mutation was published")
	}
	// A reconnect gets a fresh snapshot; no event replay/backlog is necessary.
	reconnected, _ := openStream(t, s, cfg.BasePath, cookie)
	name, payload = readEvent(t, reconnected)
	var revisions map[string]uint64
	_ = json.Unmarshal(payload["revisions"], &revisions)
	if name != "ready" || revisions["clients"] != changed["clients"] {
		t.Fatal("stale reconnect snapshot")
	}
}

func TestSSELogoutPasswordChangeAndExpirationRevokeStreams(t *testing.T) {
	for _, action := range []string{"logout", "password", "expiration"} {
		t.Run(action, func(t *testing.T) {
			h, db, cfg := fixture(t)
			s := h.(*Server)
			cookie, csrf := signIn(t, s)
			reader, _ := openStream(t, s, "", cookie)
			readEvent(t, reader)
			switch action {
			case "logout":
				if w := request(s, "POST", "/api/auth/logout", `{}`, cookie, csrf, cfg.PublicURL); w.Code != 200 {
					t.Fatal(w.Code)
				}
			case "password":
				// Revoke a different session's stream as well as the caller's.
				other, _ := signIn(t, s)
				otherReader, _ := openStream(t, s, "", other)
				readEvent(t, otherReader)
				if w := request(s, "POST", "/api/auth/password", passwordBody("correct-password-123", newTestPassword), cookie, csrf, cfg.PublicURL); w.Code != 200 {
					t.Fatal(w.Code)
				}
				for {
					name, _ := readEvent(t, otherReader)
					if name == "session-expired" {
						break
					}
				}
			case "expiration":
				if _, err := db.DB.Exec("UPDATE sessions SET expires_at=0"); err != nil {
					t.Fatal(err)
				}
				s.invalidate("audit")
			}
			for {
				name, _ := readEvent(t, reader)
				if name == "session-expired" {
					break
				}
			}
		})
	}
}

func TestEventHubCoalescesSlowReadersAndBoundsSubscriptions(t *testing.T) {
	h := newEventHub()
	reader := h.subscribe("test")
	for i := 0; i < 10000; i++ {
		h.invalidate("clients")
	}
	if len(reader.wake) != 1 || h.snapshot()["clients"] != 10001 {
		t.Fatal("unbounded queue or lost revision")
	}
	for i := 1; i < 256; i++ {
		if h.subscribe("test") == nil {
			t.Fatal("premature limit")
		}
	}
	if h.subscribe("test") != nil {
		t.Fatal("subscriber limit is missing")
	}
	h.unsubscribe(reader)
	if h.subscribe("other") == nil {
		t.Fatal("unsubscription leaked a slot")
	}
}

func TestSharedManagementSnapshotAcrossConcurrentAPIRequests(t *testing.T) {
	_, db, cfg := fixture(t)
	cfg.ManagementSocket = filepath.Join(t.TempDir(), "management.sock")
	listener, err := net.Listen("unix", cfg.ManagementSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var calls atomic.Int32
	var version atomic.Value
	version.Store("2.7.7")
	var dcoEnabled atomic.Int32
	dcoEnabled.Store(1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				fmt.Fprint(conn, ">INFO: management ready\n")
				command, _ := bufio.NewReader(conn).ReadString('\n')
				if strings.TrimSpace(command) == "status 3" {
					calls.Add(1)
					fmt.Fprintf(conn, "TITLE\tOpenVPN %s x86_64-alpine-linux-musl [SSL (OpenSSL)] [DCO]\nGLOBAL_STATS\tdco_enabled\t%d\nEND\n", version.Load(), dcoEnabled.Load())
				}
			}()
		}
	}()
	s, err := New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := signIn(t, s)
	var group sync.WaitGroup
	for i := 0; i < 15; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			path := []string{"/api/dashboard", "/api/settings", "/api/connections"}[i%3]
			if w := request(s, "GET", path, "", cookie, "", ""); w.Code != 200 {
				t.Errorf("%s: %d", path, w.Code)
			}
		}(i)
	}
	group.Wait()
	if calls.Load() != 1 {
		t.Fatalf("got %d management samples, want one shared sample", calls.Load())
	}
	assertVersion := func(body []byte, want string) {
		t.Helper()
		var payload struct {
			VPN map[string]any `json:"vpn"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		if got, exists := payload.VPN["version"]; (want == "" && exists) || (want != "" && got != want) {
			t.Fatalf("VPN version=%v, want %q", payload.VPN, want)
		}
	}
	assertVersion(request(s, "GET", "/api/dashboard", "", cookie, "", "").Body.Bytes(), "2.7.7")
	reader, _ := openStream(t, s, "", cookie)
	_, initial := readEvent(t, reader)
	var initialVPN map[string]any
	if err := json.Unmarshal(initial["vpn"], &initialVPN); err != nil || initialVPN["version"] != "2.7.7" {
		t.Fatal("SSE omitted the running server version", initialVPN, err)
	}
	if calls.Load() != 1 {
		t.Fatal("reading the version added a management request")
	}
	assertDCO := func(payload map[string]json.RawMessage, state string) {
		t.Helper()
		var vpn struct {
			DCO struct {
				State string `json:"state"`
			} `json:"dco"`
		}
		if err := json.Unmarshal(payload["vpn"], &vpn); err != nil || vpn.DCO.State != state {
			t.Fatalf("DCO state=%+v err=%v", vpn, err)
		}
	}
	assertDCO(initial, "active")
	dcoEnabled.Store(0)
	s.getLive(context.Background(), true)
	dcoEvent, dcoPayload := readEvent(t, reader)
	if dcoEvent != "state" {
		t.Fatal("DCO-only change did not publish SSE state")
	}
	assertDCO(dcoPayload, "unavailable")
	if calls.Load() != 2 {
		t.Fatal("DCO diagnostics added a management request")
	}
	version.Store("2.7.9")
	s.getLive(context.Background(), true)
	if calls.Load() != 3 {
		t.Fatal("forced common refresh did not sample management")
	}
	name, changed := readEvent(t, reader)
	var changedVPN map[string]any
	if err := json.Unmarshal(changed["vpn"], &changedVPN); err != nil || name != "state" || changedVPN["version"] != "2.7.9" {
		t.Fatal("SSE did not publish a changed version", name, changedVPN, err)
	}
	assertVersion(request(s, "GET", "/api/dashboard", "", cookie, "", "").Body.Bytes(), "2.7.9")
	listener.Close()
	s.getLive(context.Background(), true)
	assertVersion(request(s, "GET", "/api/dashboard", "", cookie, "", "").Body.Bytes(), "")
}

func TestSSEShutdownClosesIdleStream(t *testing.T) {
	h, _, _ := fixture(t)
	s := h.(*Server)
	cookie, _ := signIn(t, s)
	reader, _ := openStream(t, s, "", cookie)
	readEvent(t, reader)
	s.StopEvents()
	if _, err := reader.ReadString('\n'); err == nil {
		t.Fatal("stream survived shutdown")
	}
}
