package api

import (
	"net/http"
	"time"
)

type KubernetesCSRSupportRule struct {
	APIGroup string   `json:"api_group"`
	Resource string   `json:"resource"`
	Verbs    []string `json:"verbs"`
}

type KubernetesCSRSupport struct {
	Capability             string                     `json:"capability"`
	Served                 bool                       `json:"served"`
	GeneratedAt            string                     `json:"generated_at"`
	APIGroup               string                     `json:"api_group"`
	APIVersion             string                     `json:"api_version"`
	Resource               string                     `json:"resource"`
	SignerNames            []string                   `json:"signer_names"`
	ControllerFlow         []string                   `json:"controller_flow"`
	RBACRules              []KubernetesCSRSupportRule `json:"rbac_rules"`
	StatusFields           []string                   `json:"status_fields"`
	ArchitectureControls   []string                   `json:"architecture_controls"`
	EvidenceRefs           []string                   `json:"evidence_refs"`
	Residuals              []string                   `json:"residuals"`
	RecommendedNextActions []string                   `json:"recommended_next_actions"`
}

func (a *API) getKubernetesCSRSupport(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, buildKubernetesCSRSupport(time.Now().UTC().Format(time.RFC3339)))
}

func buildKubernetesCSRSupport(generatedAt string) KubernetesCSRSupport {
	if generatedAt == "" {
		generatedAt = "1970-01-01T00:00:00Z"
	}
	return KubernetesCSRSupport{
		Capability:  "CAP-K8S-04",
		Served:      true,
		GeneratedAt: generatedAt,
		APIGroup:    "certificates.k8s.io",
		APIVersion:  "certificates.k8s.io/v1",
		Resource:    "certificatesigningrequests",
		SignerNames: []string{
			"trstctl.com/trstctl",
			"trstctl.com/<clusterissuer-name>",
			"trstctl.com/<issuer-name> with trstctl.com/issuer-kind=Issuer",
		},
		ControllerFlow: []string{
			"DaemonSet trstctl-agent runs --cert-manager-controller with a mounted certs:issue API token",
			"controller lists certificates.k8s.io/v1 CertificateSigningRequests",
			"controller signs only Approved requests whose signerName maps to an existing trstctl Issuer or ClusterIssuer",
			"CSR DER or PEM bytes are forwarded to the served trstctl issuance endpoint with a stable Idempotency-Key",
			"issued certificate chain is written to status.certificate and Ready=True is upserted",
		},
		RBACRules: []KubernetesCSRSupportRule{
			{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests", Verbs: []string{"get", "list", "watch"}},
			{APIGroup: "certificates.k8s.io", Resource: "certificatesigningrequests/status", Verbs: []string{"update", "patch"}},
		},
		StatusFields: []string{
			"status.certificate",
			"status.conditions[type=Ready]",
		},
		ArchitectureControls: []string{
			"only approved CertificateSigningRequests are signed",
			"signerName must map to an existing trstctl Issuer or ClusterIssuer",
			"the agent writes the status subresource only and never approves requests itself",
			"only CSR bytes cross the control-plane boundary; private keys stay with the workload or Kubernetes client",
			"the HTTP signer uses a stable Idempotency-Key so retries do not mint duplicates",
		},
		EvidenceRefs: []string{
			"internal/agent/k8s/certificate_signing_request.go",
			"internal/agent/k8s/issuer_controller.go",
			"internal/agent/k8s/signer.go",
			"deploy/kubernetes/rbac.yaml",
			"deploy/kubernetes/daemonset.yaml",
			"internal/server/kubernetes_csr_served_test.go",
		},
		Residuals: []string{
			"the controller is poll-based rather than informer/workqueue-backed",
			"approval policy remains a Kubernetes approver responsibility; trstctl signs only requests Kubernetes has already approved",
			"multi-cluster rollout uses one DaemonSet/install per cluster",
		},
		RecommendedNextActions: []string{
			"move reconciliation to informer-backed queues for very large clusters",
			"publish sample approver policy for signerName-to-tenant/profile governance",
			"add per-CSR delivery receipts to the operations queue",
		},
	}
}
