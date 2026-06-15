// Package est implements the RFC 7030 EST enrollment server for device
// enrollment.
//
// Status: this is a complete, tested implementation (/cacerts + /simpleenroll +
// /simplereenroll round-trips, a fuzzed parser, and an external-reference
// differential against OpenSSL's PKCS#7 — plus the libest client on the CI
// backstop), NOT a placeholder. It is library code that is not yet mounted on the
// served control-plane listener of the running binary; serving it (with auth and
// tenant scoping) is tracked as EXC-WIRE-02. See docs/limitations.md "Protocols".
package est
