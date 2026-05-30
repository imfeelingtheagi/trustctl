//go:build unix

package drift

import "os"

// modeDrifted reports whether the on-disk permission bits differ from the
// declared mode. On POSIX hosts the permission bits are the access-control
// mechanism, so a loosened key (0600 -> 0644) is real drift. A zero declared
// mode skips the check.
func modeDrifted(actual, declared os.FileMode) bool {
	return declared != 0 && actual.Perm() != declared.Perm()
}
