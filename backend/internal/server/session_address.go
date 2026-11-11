package server

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

func (s *Server) trustedProxy(ip netip.Addr) bool {
	for _, prefix := range s.cfg.TrustedProxies {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// Resolve the client address for session metadata and sign-in IP limits.
// Walk XFF from the direct peer backwards, stopping at the first untrusted hop.
func (s *Server) loginAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || peer.Zone() != "" {
		return ""
	}
	peer = peer.Unmap()
	if !s.trustedProxy(peer) {
		return peer.String()
	}
	forwarded := r.Header.Values("X-Forwarded-For")
	if len(forwarded) == 0 {
		if ip, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil && ip.Zone() == "" {
			return ip.Unmap().String()
		}
		return peer.String()
	}
	chain := strings.Join(forwarded, ",")
	if len(chain) > 4096 {
		return peer.String()
	}
	ips := strings.Split(chain, ",")
	address := peer
	for i := len(ips) - 1; i >= 0 && s.trustedProxy(address); i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(ips[i]))
		if err != nil || ip.Zone() != "" {
			return peer.String()
		}
		address = ip.Unmap()
	}
	return address.String()
}
