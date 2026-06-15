// Package scep implements the RFC 8894 SCEP enrollment server, compatible with
// MDM-style clients.
//
// Status: this is a complete, tested implementation (a real PKIOperation enroll
// round-trip plus a fuzzed parser), NOT a placeholder. It is library code that is
// not yet mounted on the served control-plane listener of the running binary;
// serving it (with auth and tenant scoping) is tracked as EXC-WIRE-02. See
// docs/limitations.md "Protocols" for the served-vs-library status.
package scep
