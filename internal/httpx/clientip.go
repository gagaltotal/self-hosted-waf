// Package httpx holds small HTTP helpers shared between the proxy and the
// admin API.
package httpx

import (
	"net"
	"net/http"
	"strings"
)

// TrustedProxies resolves the real client IP for a request. This is
// security-critical: if forwarded headers were trusted unconditionally, any
// attacker could set X-Forwarded-For to an arbitrary value and completely
// bypass IP-based rate limiting and IP blocklists. We only look at
// X-Forwarded-For / X-Real-IP when the direct TCP peer is itself a
// configured trusted proxy (e.g. your load balancer or CDN); otherwise the
// raw connection address is used, always.
type TrustedProxies struct {
	nets []*net.IPNet
}

func NewTrustedProxies(cidrs []string) *TrustedProxies {
	tp := &TrustedProxies{}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// Allow bare IPs as well as CIDRs.
		if !strings.Contains(c, "/") {
			if strings.Contains(c, ":") {
				c += "/128"
			} else {
				c += "/32"
			}
		}
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			tp.nets = append(tp.nets, n)
		}
	}
	return tp
}

func (tp *TrustedProxies) contains(ip net.IP) bool {
	for _, n := range tp.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the best-effort real client IP for r.
func (tp *TrustedProxies) ClientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	peerIP := net.ParseIP(remoteHost)

	if peerIP == nil || len(tp.nets) == 0 || !tp.contains(peerIP) {
		// Direct peer is not a trusted proxy: never trust forwarded headers.
		if peerIP != nil {
			return peerIP.String()
		}
		return remoteHost
	}

	// Peer is a trusted proxy: the left-most address in X-Forwarded-For is
	// the original client, as long as it parses as a valid IP.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		first := strings.TrimSpace(parts[0])
		if ip := net.ParseIP(first); ip != nil {
			return ip.String()
		}
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		if ip := net.ParseIP(xrip); ip != nil {
			return ip.String()
		}
	}
	if peerIP != nil {
		return peerIP.String()
	}
	return remoteHost
}
