package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256Hex returns the lowercase hex-encoded SHA-256 digest of data. It lives
// in the crypto boundary so build and release tooling (for example, publishing
// artifact checksums) can compute digests without importing crypto/* directly
// (AN-3).
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
