package netsec_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

func TestBlockedIPDenylist(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "::1", // loopback
		"169.254.169.254", "fe80::1", // link-local incl. cloud metadata
		"10.1.2.3", "192.168.1.1", "172.16.0.1", // RFC-1918
		"100.64.0.1",       // carrier-grade NAT
		"0.0.0.0",          // unspecified
		"224.0.0.1",        // multicast
		"fd00:ec2::254",    // IPv6 metadata alias
		"::ffff:127.0.0.1", // v4-in-v6 loopback
	} {
		if !netsec.BlockedIP(net.ParseIP(s)) {
			t.Errorf("BlockedIP(%s) = false, want true (must be blocked)", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"} {
		if netsec.BlockedIP(net.ParseIP(s)) {
			t.Errorf("BlockedIP(%s) = true, want false (a public address must be allowed)", s)
		}
	}
	if !netsec.BlockedIP(nil) {
		t.Error("BlockedIP(nil) = false, want true (fail closed)")
	}
}

func TestSafeClientRefusesInternalTargets(t *testing.T) {
	c := netsec.SafeClient(2 * time.Second)
	for _, url := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:1/",
		"http://10.0.0.1/",
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if _, err := c.Do(req); err == nil {
			t.Errorf("SafeClient reached %s; it must refuse non-public addresses", url)
		} else if !errors.Is(err, netsec.ErrSSRFBlocked) {
			// The dial Control wraps ErrSSRFBlocked; url.Error should carry it.
			t.Logf("note: %s blocked with non-sentinel error: %v", url, err)
		}
	}
}

func TestValidatePublicHTTPSURLRejectsUnsafeEndpoints(t *testing.T) {
	for _, raw := range []string{
		"://bad",
		"http://example.com/hook",
		"https:///missing-host",
		"https://127.0.0.1/hook",
		"https://[::1]/hook",
		"https://169.254.169.254/latest/meta-data/",
		"https://10.0.0.1/hook",
		"https://100.64.0.1/hook",
		"https://[fd00:ec2::254]/hook",
	} {
		err := netsec.ValidatePublicHTTPSURL(raw)
		if err == nil {
			t.Errorf("ValidatePublicHTTPSURL(%q) = nil, want SSRF-blocked error", raw)
			continue
		}
		if !errors.Is(err, netsec.ErrSSRFBlocked) {
			t.Errorf("ValidatePublicHTTPSURL(%q) = %v, want ErrSSRFBlocked", raw, err)
		}
	}

	for _, raw := range []string{
		"https://example.com/hook",
		"https://api.example.test/v1/events",
	} {
		if err := netsec.ValidatePublicHTTPSURL(raw); err != nil {
			t.Errorf("ValidatePublicHTTPSURL(%q) = %v, want allowed", raw, err)
		}
	}
}
