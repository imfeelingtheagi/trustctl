//go:build !linux

package signing

// Harden is a no-op on non-Linux platforms (Linux is the production target).
func Harden() error { return nil }
