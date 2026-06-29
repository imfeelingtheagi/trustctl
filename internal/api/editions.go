package api

import (
	"net/http"

	"trstctl.com/trstctl/internal/compliance"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
)

type editionsResponse struct {
	license.Info
	FIPS fipsPostureResponse `json:"fips"`
}

type fipsPostureResponse struct {
	crypto.FIPSStatus
	CapabilityID                 string                                    `json:"capability_id"`
	ValidatedModulePath          bool                                      `json:"validated_module_path"`
	Standard                     string                                    `json:"standard"`
	Module                       string                                    `json:"module"`
	BuildTarget                  string                                    `json:"build_target"`
	RuntimeActivation            []string                                  `json:"runtime_activation"`
	CIGate                       string                                    `json:"ci_gate"`
	CryptoBoundary               string                                    `json:"crypto_boundary"`
	ProductCertificationResidual string                                    `json:"product_certification_residual"`
	RegulatedDeploymentProfile   compliance.FIPSRegulatedDeploymentProfile `json:"regulated_deployment_profile"`
}

func (a *API) licenseManager() *license.Manager {
	if a != nil && a.license != nil {
		return a.license
	}
	return license.Community()
}

func (a *API) getEditions(w http.ResponseWriter, _ *http.Request) {
	fips, err := crypto.PowerOnSelfTest(false)
	if err != nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "crypto power-on self-test failed"))
		return
	}
	a.writeJSON(w, http.StatusOK, editionsResponse{
		Info: a.licenseManager().Info(),
		FIPS: fipsPosture(fips),
	})
}

func fipsPosture(status crypto.FIPSStatus) fipsPostureResponse {
	return fipsPostureResponse{
		FIPSStatus:          status,
		CapabilityID:        "CAP-KEY-03",
		ValidatedModulePath: true,
		Standard:            "FIPS 140-3",
		Module:              "Go Cryptographic Module",
		BuildTarget:         "make fips-build",
		RuntimeActivation: []string{
			"GOFIPS140=" + compliance.DefaultFIPSGoModuleSelector,
			"GOFIPS140=latest override for compatibility testing only",
			"GODEBUG=fips140=on",
			"--fips / TRSTCTL_FIPS=1 fail-closed startup assertion",
		},
		CIGate:                       "fips-capable build (GOFIPS140)",
		CryptoBoundary:               "internal/crypto (AN-3) is the only package that imports crypto/*; control-plane and signer code call it through boundary interfaces",
		ProductCertificationResidual: "The trstctl product NIST CMVP certificate and deployment-specific approved configuration remain an external residual.",
		RegulatedDeploymentProfile:   compliance.RegulatedFIPSDeploymentProfile(status),
	}
}
