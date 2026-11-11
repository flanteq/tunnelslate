package vpnauth

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"net"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

func TestRADIUSAcceptRejectAndIntegrity(t *testing.T) {
	for _, mode := range []string{"accept", "reject", "challenge", "missing_mac", "bad_mac", "bad_response", "wrong_id"} {
		t.Run(mode, func(t *testing.T) {
			conn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			p := radiusProvider()
			p.Config.Address = conn.LocalAddr().String()
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 4096)
				n, addr, e := conn.ReadFrom(buf)
				if e != nil {
					return
				}
				request := buf[:n]
				if !validMessageAuthenticator(request, request[4:20], []byte(p.Secret)) {
					t.Error("unsigned request")
					return
				}
				parsed, e := radius.Parse(request, []byte(p.Secret))
				if e != nil {
					t.Error(e)
					return
				}
				if rfc2865.UserName_GetString(parsed) != "alice" || rfc2865.UserPassword_GetString(parsed) != "correct-password" {
					t.Error("credentials changed")
				}
				code := radius.CodeAccessAccept
				if mode == "reject" {
					code = radius.CodeAccessReject
				}
				if mode == "challenge" {
					code = radius.CodeAccessChallenge
				}
				response := parsed.Response(code)
				if mode != "missing_mac" {
					_ = rfc2869.MessageAuthenticator_Set(response, make([]byte, 16))
				}
				wire, e := response.Encode()
				if e != nil {
					t.Error(e)
					return
				}
				copy(wire[4:20], request[4:20])
				if mode != "missing_mac" {
					offset, _ := messageAuthenticatorOffset(wire)
					mac := hmac.New(md5.New, []byte(p.Secret))
					mac.Write(wire)
					copy(wire[offset:offset+16], mac.Sum(nil))
					if mode == "bad_mac" {
						wire[offset] ^= 1
					}
				}
				if mode == "wrong_id" {
					wire[1] ^= 1
				}
				hash := md5.New()
				hash.Write(wire)
				hash.Write([]byte(p.Secret))
				copy(wire[4:20], hash.Sum(nil))
				if mode == "bad_response" {
					wire[4] ^= 1
				}
				_, _ = conn.WriteTo(wire, addr)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			accepted, err := authenticateRADIUS(ctx, p, "alice", "correct-password", "192.0.2.1")
			if mode == "accept" {
				if !accepted || err != nil {
					t.Fatal(accepted, err)
				}
			} else if accepted {
				t.Fatal("invalid response accepted")
			}
			if mode == "reject" && err != nil {
				t.Fatal(err)
			}
			conn.Close()
			<-done
		})
	}
}
