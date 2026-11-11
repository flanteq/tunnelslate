package vpnauth

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
	"tunnelslate/internal/vpnauthwire"
)

func TestRADIUSTimeoutValidationPersistenceAndLegacyDefault(t *testing.T) {
	s := fixture(t)
	ctx := context.Background()
	for _, seconds := range []int{-1, 1, 4, 301} {
		p := radiusProvider()
		p.Config.TimeoutSeconds = seconds
		_, err := s.SaveProvider(ctx, p, "admin")
		var problem *Error
		if !errors.As(err, &problem) || problem.Code != "vpn_auth.invalid_radius_timeout" {
			t.Fatalf("timeout %d: %v", seconds, err)
		}
	}
	p, err := s.SaveProvider(ctx, radiusProvider(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if p.Config.TimeoutSeconds != 90 {
		t.Fatal("missing default", p.Config)
	}
	p.Config.TimeoutSeconds = 300
	p, err = s.SaveProvider(ctx, p, "admin")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.provider(ctx, p.ID)
	if err != nil || got.Config.TimeoutSeconds != 300 {
		t.Fatal("timeout not persisted", got.Config, err)
	}
	if _, err = s.Store.DB.Exec(`UPDATE vpn_auth_providers SET configuration=json_remove(configuration,'$.timeout_seconds')`); err != nil {
		t.Fatal(err)
	}
	listed, err := s.Providers(ctx)
	if err != nil || listed[0].Config.TimeoutSeconds != 90 {
		t.Fatal("legacy list default", listed, err)
	}
	got, err = s.provider(ctx, p.ID)
	if err != nil || providerTimeout(got) != 90*time.Second {
		t.Fatal("legacy runtime default", got.Config, err)
	}
}

// A real UDP response delayed past all previous 8/10/12-second limits must
// reach both the panel's provider test and the Unix socket used by vpn-auth.
func TestRADIUSMFAWaitThroughProviderTestAndBroker(t *testing.T) {
	s := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 22*time.Second)
	defer cancel()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	p := radiusProvider()
	p.Config.Address = conn.LocalAddr().String()
	p.Config.TimeoutSeconds = 20
	p, err = s.SaveProvider(ctx, p, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveBinding(ctx, "client", Binding{Mode: "external", ProviderID: p.ID, Username: "alice"}, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Store.DB.Exec("DELETE FROM vpn_auth_disconnects"); err != nil {
		t.Fatal(err)
	}
	if err = s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	requests := make(chan struct{}, 2)
	replyErrors := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			buffer := make([]byte, 4096)
			n, addr, e := conn.ReadFrom(buffer)
			if e != nil {
				replyErrors <- e
				return
			}
			requests <- struct{}{}
			packet, e := radius.Parse(buffer[:n], []byte("a-test-shared-secret"))
			if e != nil {
				replyErrors <- e
				return
			}
			response := packet.Response(radius.CodeAccessAccept)
			_ = rfc2869.MessageAuthenticator_Set(response, make([]byte, 16))
			wire, e := response.Encode()
			if e != nil {
				replyErrors <- e
				return
			}
			copy(wire[4:20], buffer[4:20])
			offset, e := messageAuthenticatorOffset(wire)
			if e != nil {
				replyErrors <- e
				return
			}
			mac := hmac.New(md5.New, packet.Secret)
			mac.Write(wire)
			copy(wire[offset:offset+16], mac.Sum(nil))
			hash := md5.New()
			hash.Write(wire)
			hash.Write(packet.Secret)
			copy(wire[4:20], hash.Sum(nil))
			select {
			case <-time.After(13 * time.Second):
			case <-ctx.Done():
				replyErrors <- ctx.Err()
				return
			}
			_, e = conn.WriteTo(wire, addr)
			replyErrors <- e
		}()
	}
	tested := make(chan error, 1)
	go func() { tested <- s.Test(ctx, p.ID, "alice", "password") }()
	socket, err := net.DialTimeout("unix", s.ControlDir+"/"+vpnauthwire.SocketName, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_ = socket.SetDeadline(time.Now().Add(21 * time.Second))
	request := vpnauthwire.Request{CommonName: "desk-11111111111111111111111111111111", Serial: "ABCDEF", IP: "192.0.2.1", Username: "alice", Password: "password"}
	if err = json.NewEncoder(socket).Encode(request); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-requests:
		case <-ctx.Done():
			t.Fatal("no RADIUS request", ctx.Err())
		}
	}
	var response vpnauthwire.Response
	if err = json.NewDecoder(socket).Decode(&response); err != nil {
		t.Fatal("broker stopped waiting for MFA", err)
	}
	if !response.Allowed || len(response.Version) != 64 {
		t.Fatal("delayed MFA denied", response)
	}
	if err = <-tested; err != nil {
		t.Fatal("panel test stopped waiting for MFA", err)
	}
	for i := 0; i < 2; i++ {
		if err = <-replyErrors; err != nil {
			t.Fatal(err)
		}
	}
}

func TestRADIUSTimeoutStillCancelsUnansweredRequests(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	p := radiusProvider()
	p.Config.Address = conn.LocalAddr().String()
	p.Config.TimeoutSeconds = 5
	start := time.Now()
	ok, err := authenticateRADIUS(context.Background(), p, "alice", "password", "192.0.2.1")
	elapsed := time.Since(start)
	if ok || err == nil || elapsed < 4*time.Second || elapsed > 7*time.Second {
		t.Fatal("configured timeout not enforced", ok, err, elapsed)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	if ok, err = authenticateRADIUS(ctx, p, "alice", "password", "192.0.2.1"); ok || err == nil || time.Since(start) > time.Second {
		t.Fatal("cancellation ignored", ok, err)
	}
}
