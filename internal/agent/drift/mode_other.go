//go:build !unix

package drift

import "os"

// modeDrifted is a no-op off POSIX. Go's FileMode bits are not the
// access-control mechanism on Windows (NTFS ACLs and the certificate store are),
// so permission drift is not inferred from FileMode there — consistent with the
// filesystem destination (S5.2/S5.3), which does not rely on mode bits on
// Windows.
func modeDrifted(_, _ os.FileMode) bool { return false }
