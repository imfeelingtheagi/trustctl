//go:build !linux

package signing

import "net"

// peerUID cannot determine the peer uid on non-Linux platforms; the socket's
// filesystem permissions remain the access control there.
func peerUID(net.Conn) (int, bool) { return 0, false }

func peerCredentialsSupported() bool { return false }
