package signing

import "net"

// peerAuthListener restricts accepted UDS connections to a single uid (the
// control plane's), as defense in depth on top of the socket's filesystem
// permissions. When the peer uid cannot be determined (non-Linux), it accepts —
// the filesystem permissions remain the access control there.
type peerAuthListener struct {
	net.Listener
	allowedUID int
}

func newPeerAuthListener(ln net.Listener, allowedUID int) net.Listener {
	return &peerAuthListener{Listener: ln, allowedUID: allowedUID}
}

func (l *peerAuthListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if uid, ok := peerUID(c); !ok || uid == l.allowedUID {
			return c, nil
		}
		_ = c.Close() // reject a peer whose uid does not match
	}
}
