package operator

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCRDIsValid(t *testing.T) {
	var crd struct {
		APIVersion string `yaml:"apiVersion"`
		Kind       string `yaml:"kind"`
		Spec       struct {
			Group string `yaml:"group"`
			Names struct {
				Kind   string `yaml:"kind"`
				Plural string `yaml:"plural"`
			} `yaml:"names"`
			Versions []struct {
				Name    string `yaml:"name"`
				Served  bool   `yaml:"served"`
				Storage bool   `yaml:"storage"`
			} `yaml:"versions"`
		} `yaml:"spec"`
	}
	b, err := os.ReadFile("crd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &crd); err != nil {
		t.Fatalf("crd.yaml is not valid YAML: %v", err)
	}
	if crd.Kind != "CustomResourceDefinition" {
		t.Errorf("kind = %q", crd.Kind)
	}
	if crd.Spec.Group != "trustctl.io" || crd.Spec.Names.Kind != "TrustctlControlPlane" {
		t.Errorf("CRD group/kind = %q/%q", crd.Spec.Group, crd.Spec.Names.Kind)
	}
	if len(crd.Spec.Versions) == 0 || !crd.Spec.Versions[0].Served || !crd.Spec.Versions[0].Storage {
		t.Error("CRD has no served+stored version")
	}
}

// TestOperatorDocIsHonestAndCodeBound pins OPS-004: the package doc.go must not
// over-claim a built, kind-tested operator controller while no such controller or
// image exists. It is code-bound in BOTH directions:
//   - while there is no cmd/trustctl-operator (the controller binary), doc.go must
//     disclose the operator as PLANNED/not-yet-shipped and must NOT claim the
//     controller image is built or integration-tested on CI/kind (the original
//     over-claim);
//   - if a future change adds the controller binary, the stale "planned/not shipped"
//     wording must be retired (caught here so the doc cannot lie the other way).
//
// This is the package-doc counterpart to docs/docs_test.go
// TestKubernetesControlPlaneDeploymentIsReal, which guards the product docs.
func TestOperatorDocIsHonestAndCodeBound(t *testing.T) {
	doc, err := os.ReadFile("doc.go")
	if err != nil {
		t.Fatalf("read doc.go: %v", err)
	}
	src := string(doc)
	low := strings.ToLower(src)

	// Reality anchor: the controller binary the operator would build into an image.
	_, statErr := os.Stat("../../cmd/trustctl-operator")
	controllerExists := statErr == nil

	if controllerExists {
		// The operator is now real: the not-yet-shipped disclosure would be a stale
		// under-claim and must be gone.
		if strings.Contains(low, "planned, not yet shipped") || strings.Contains(low, "not yet shipped") {
			t.Error("cmd/trustctl-operator now exists, but doc.go still calls the operator not-yet-shipped — update the disclosure (OPS-004)")
		}
		return
	}

	// Not shipped: doc.go must say so, cite S15.1, and carry NO over-claim that the
	// controller image is built / integration-tested on CI (kind).
	if !strings.Contains(low, "planned") || !strings.Contains(src, "S15.1") {
		t.Error("doc.go must disclose the operator as PLANNED (S15.1) while no controller binary exists (OPS-004)")
	}
	overClaims := []string{
		"controller image is built and integration-tested",
		"built and integration-tested on ci",
		"built+kind-tested",
		"kind-tested",
		"the operator is built and tested",
	}
	for _, oc := range overClaims {
		if strings.Contains(low, oc) {
			t.Errorf("doc.go over-claims a built/tested operator (%q) while there is no cmd/trustctl-operator and no image build (OPS-004/OPS-002)", oc)
		}
	}
	// It must point at the manifests-only reality (not advertise a deployable
	// controller).
	if !strings.Contains(low, "manifest") {
		t.Error("doc.go should state the package ships only manifests (CRD + RBAC + Deployment) + structural validation, not a deployable controller (OPS-004)")
	}
}

func TestOperatorManifestHasRBACAndIsolatedDeployment(t *testing.T) {
	b, err := os.ReadFile("operator.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Each YAML document must parse.
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	docs := 0
	for {
		var doc any
		if err := dec.Decode(&doc); err != nil {
			break
		}
		docs++
	}
	if docs < 4 {
		t.Errorf("operator.yaml has %d documents, want >=4 (SA, ClusterRole, Binding, Deployment)", docs)
	}
	body := string(b)
	for _, want := range []string{"kind: ServiceAccount", "kind: ClusterRole", "kind: ClusterRoleBinding", "kind: Deployment", "trustctl.io", "runAsNonRoot: true", "readOnlyRootFilesystem: true"} {
		if !strings.Contains(body, want) {
			t.Errorf("operator.yaml missing %q", want)
		}
	}
}
