package server

import (
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/profile"
)

func intendedProfileEKUs(requested, allowed []string) []string {
	if len(requested) > 0 {
		return cloneStrings(requested)
	}
	if len(allowed) > 0 {
		return cloneStrings(allowed)
	}
	return nil
}

func leafProfileForCertificateProfile(base crypto.LeafProfile, prof profile.CertificateProfile, intendedEKUs []string) crypto.LeafProfile {
	out := base
	if prof.MaxValidity > 0 {
		max := time.Duration(prof.MaxValidity)
		if out.MaxValidity == 0 || max < out.MaxValidity {
			out.MaxValidity = max
		}
	}
	if len(intendedEKUs) > 0 {
		out.AllowedExtKeyUsage = cloneStrings(intendedEKUs)
	}
	if len(prof.AllowedDNSSuffixes) > 0 && len(out.PermittedDNSSuffixes) == 0 {
		out.PermittedDNSSuffixes = cloneStrings(prof.AllowedDNSSuffixes)
	}
	return out
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
