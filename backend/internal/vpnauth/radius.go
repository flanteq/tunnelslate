package vpnauth

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"net"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

// RADIUS PAP only. Require Message-Authenticator in requests AND replies;
// Response Authenticator alone is not sufficient against Blast-RADIUS.
func authenticateRADIUS(ctx context.Context, p Provider, username, password, ip string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, providerTimeout(p))
	defer cancel()
	if len(password) > 128 {
		return false, nil
	}
	packet := radius.New(radius.CodeAccessRequest, []byte(p.Secret))
	if err := rfc2865.UserName_SetString(packet, username); err != nil {
		return false, err
	}
	if err := rfc2865.UserPassword_SetString(packet, password); err != nil {
		return false, err
	}
	if err := rfc2865.NASIdentifier_SetString(packet, p.Config.NASIdentifier); err != nil {
		return false, err
	}
	if err := rfc2865.CallingStationID_SetString(packet, ip); err != nil {
		return false, err
	}
	if err := rfc2869.MessageAuthenticator_Set(packet, make([]byte, 16)); err != nil {
		return false, err
	}
	wire, err := packet.Encode()
	if err != nil {
		return false, err
	}
	offset, err := messageAuthenticatorOffset(wire)
	if err != nil {
		return false, err
	}
	mac := hmac.New(md5.New, packet.Secret)
	mac.Write(wire)
	copy(wire[offset:offset+16], mac.Sum(nil))
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", p.Config.Address)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	end, _ := ctx.Deadline()
	if err = conn.SetDeadline(end); err != nil {
		return false, err
	}
	if _, err = conn.Write(wire); err != nil {
		return false, err
	}
	response := make([]byte, radius.MaxPacketLength)
	for attempt := 0; attempt < 16; attempt++ {
		n, err := conn.Read(response)
		if err != nil {
			return false, err
		}
		b := response[:n]
		if n < 20 || b[1] != wire[1] || !radius.IsAuthenticResponse(b, wire, packet.Secret) {
			continue
		}
		if !validMessageAuthenticator(b, wire[4:20], packet.Secret) {
			continue
		}
		parsed, err := radius.Parse(b, packet.Secret)
		if err != nil {
			continue
		}
		switch parsed.Code {
		case radius.CodeAccessAccept:
			return true, nil
		case radius.CodeAccessReject:
			return false, nil
		default:
			return false, errors.New("RADIUS challenge is not supported")
		}
	}
	return false, errors.New("RADIUS response failed integrity validation")
}
func messageAuthenticatorOffset(wire []byte) (int, error) {
	if len(wire) < 20 || int(wire[2])<<8|int(wire[3]) != len(wire) {
		return 0, errors.New("invalid RADIUS packet")
	}
	found := 0
	for i := 20; i < len(wire); {
		if i+2 > len(wire) || wire[i+1] < 2 || i+int(wire[i+1]) > len(wire) {
			return 0, errors.New("invalid RADIUS attribute")
		}
		if wire[i] == 80 {
			if wire[i+1] != 18 || found != 0 {
				return 0, errors.New("invalid Message-Authenticator")
			}
			found = i + 2
		}
		i += int(wire[i+1])
	}
	if found == 0 {
		return 0, errors.New("missing Message-Authenticator")
	}
	return found, nil
}
func validMessageAuthenticator(wire, requestAuthenticator, secret []byte) bool {
	offset, err := messageAuthenticatorOffset(wire)
	if err != nil || len(requestAuthenticator) != 16 {
		return false
	}
	b := append([]byte(nil), wire...)
	expected := append([]byte(nil), b[offset:offset+16]...)
	copy(b[4:20], requestAuthenticator)
	clear(b[offset : offset+16])
	mac := hmac.New(md5.New, secret)
	mac.Write(b)
	return hmac.Equal(expected, mac.Sum(nil))
}
