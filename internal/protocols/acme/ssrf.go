package acme

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// ErrSSRFBlocked is returned when an ACME challenge fetch is aimed at an address
// in a blocked range (loopback, link-local incl. the cloud metadata service,
// private/RFC-1918, unique-local, unspecified, or multicast). The challenge
// identifier is attacker-influenced, so a CA that fetched it unguarded could be
// coerced into reaching internal endpoints — classic CA SSRF (SEC-006). We fail
// closed instead.
var ErrSSRFBlocked = errors.New("acme: refusing to connect to a non-public address (SSRF guard)")

// blockedIP reports whether ip is in a range an outbound challenge fetch must
// never reach. It is the SSRF denylist (SEC-006): loopback (127/8, ::1),
// link-local (169.254/16 incl. the 169.254.169.254 cloud-metadata service, and
// fe80::/10), the IPv6 metadata alias fd00:ec2::254, private RFC-1918 ranges,
// IPv6 unique-local (fc00::/7), carrier-grade NAT (100.64/10), the unspecified
// address, and multicast. It evaluates the RESOLVED address, so DNS that points a
// public name at an internal IP is still caught.
func blockedIP(ip net.IP) bool {
	if ip == nil {
		return true // unparseable → refuse
	}
	// Normalize to the canonical form so v4-in-v6 (::ffff:a.b.c.d) is matched as v4.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	// Carrier-grade NAT (RFC 6598) is not covered by IsPrivate; treat it as internal.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 { // 100.64.0.0/10
			return true
		}
	}
	// The IPv6 alias some clouds expose for the metadata service.
	if ip.Equal(net.ParseIP("fd00:ec2::254")) {
		return true
	}
	return false
}

// safeDialControl is a net.Dialer.Control callback that rejects a connection
// whose resolved address is in a blocked range (SEC-006). Because Control runs
// AFTER name resolution and immediately BEFORE connect — on the actual IP the
// socket will use, for every attempt including each redirect hop — it defeats
// DNS-rebinding: an attacker cannot resolve a public name to a private IP and
// slip past a pre-check, because the IP that is actually dialed is the one
// validated here.
func safeDialControl(_ /*network*/ string, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSSRFBlocked, err)
	}
	ip := net.ParseIP(host)
	if blockedIP(ip) {
		return fmt.Errorf("%w: %s", ErrSSRFBlocked, host)
	}
	return nil
}

// ssrfSafeTransport returns an *http.Transport whose dialer validates every
// resolved address against the SSRF denylist (SEC-006). It is used by the HTTP-01
// validator's default client.
func ssrfSafeTransport() *http.Transport {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: safeDialControl}
	return &http.Transport{
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		// Don't reuse a connection across hosts/redirects — each dial is re-validated.
		DisableKeepAlives: true,
	}
}

// ssrfSafeClient returns an *http.Client safe to point at an attacker-influenced
// challenge URL (SEC-006): its transport blocks non-public resolved addresses,
// and its redirect policy both bounds the redirect chain and re-validates each
// hop's host (the dial Control catches the IP, and this catches a literal-IP
// Location before the dial). It is the default client for HTTP-01 validation.
func ssrfSafeClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: ssrfSafeTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("acme: too many redirects")
			}
			// Only http/https challenge fetches are legitimate; a redirect to file://,
			// gopher://, etc. is refused outright.
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("%w: redirect to scheme %q", ErrSSRFBlocked, req.URL.Scheme)
			}
			// If the redirect target is a literal IP, validate it here too (the dial
			// Control is the authoritative check for names, which resolve at dial time).
			if ip := net.ParseIP(req.URL.Hostname()); ip != nil && blockedIP(ip) {
				return fmt.Errorf("%w: redirect to %s", ErrSSRFBlocked, req.URL.Hostname())
			}
			return nil
		},
	}
}
