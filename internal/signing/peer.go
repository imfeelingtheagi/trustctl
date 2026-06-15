package signing

import "net"

// peerAuthListener restricts accepted UDS connections to a single uid (the
// control plane's), as defense in depth on top of the socket's filesystem
// permissions. When the peer uid cannot be determined (non-Linux, where
// SO_PEERCRED is unavailable — see peercred_other.go; or an error reading the
// credential), it accepts: the 0700 socket directory + 0600 socket remain the
// access control there. Linux (the supported production target: Docker/Helm) gets
// the peer-uid layer on top. This non-Linux fallback is the WIRE-009/SIGNER-006
// disclosure — peer-uid is defense-in-depth, not the primary control.
type peerAuthListener struct {
	net.Listener
	allowedUID int
	// peerUID resolves the connecting process's uid. It is a field (defaulting to
	// the platform peerUID) so the rejection path is unit-testable without a real
	// cross-uid socket (SIGNER-006: the rejection branch was previously untested,
	// so a regression breaking the uid comparison would pass CI silently).
	peerUID func(net.Conn) (int, bool)
}

func newPeerAuthListener(ln net.Listener, allowedUID int) net.Listener {
	return &peerAuthListener{Listener: ln, allowedUID: allowedUID, peerUID: peerUID}
}

func (l *peerAuthListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if uid, ok := l.peerUID(c); !ok || uid == l.allowedUID {
			return c, nil
		}
		_ = c.Close() // reject a peer whose uid does not match
	}
}
