package operator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDecideActionDiff pins the pure desired-vs-actual diff at the heart of the
// reconcile (OPS-004): the controller must CREATE when no Deployment exists,
// UPDATE when the live replicas or image drift from the spec, and do NOTHING
// when they already match. This is the decision a real controller makes; pinning
// it here proves the operator is a genuine reconcile, not a stub.
func TestDecideActionDiff(t *testing.T) {
	spec := ControlPlaneSpec{Replicas: 3, Image: "ghcr.io/ctlplne/trstctl:v1.2.3"}

	cases := []struct {
		name string
		live deploymentState
		want Action
	}{
		{"missing deployment -> create", deploymentState{exists: false}, ActionCreate},
		{"replica drift -> update", deploymentState{exists: true, replicas: 1, image: "ghcr.io/ctlplne/trstctl:v1.2.3"}, ActionUpdate},
		{"image drift -> update", deploymentState{exists: true, replicas: 3, image: "ghcr.io/ctlplne/trstctl:OLD"}, ActionUpdate},
		{"in sync -> none", deploymentState{exists: true, replicas: 3, image: "ghcr.io/ctlplne/trstctl:v1.2.3", configHash: spec.desiredConfigHash()}, ActionNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideAction(spec, tc.live); got != tc.want {
				t.Errorf("decideAction(%+v) = %q, want %q", tc.live, got, tc.want)
			}
		})
	}
}

// fakeCluster is an in-memory Kubernetes API server scoped to the verbs the
// operator uses: it serves a TrstctlControlPlane list and a Deployment GET, and
// records the operator's Deployment create/patch and the CR status patch so the
// test can assert what the controller actually DID over the wire.
type fakeCluster struct {
	mu sync.Mutex

	// tcps is the TrstctlControlPlane list the operator reconciles.
	tcps []map[string]any
	// deployments maps name -> the live Deployment object (nil => 404, i.e. it
	// does not exist yet).
	deployments map[string]map[string]any
	// leases maps name -> coordination.k8s.io Lease object for leader election.
	leases map[string]map[string]any

	// Recorded effects:
	created      []map[string]any          // Deployment POST bodies
	patched      map[string][]byte         // Deployment name -> strategic-merge-patch body
	statusSet    map[string]map[string]any // CR name -> status patch
	leasePatches int
}

func newFakeCluster() *fakeCluster {
	return &fakeCluster{
		deployments: map[string]map[string]any{},
		leases:      map[string]map[string]any{},
		patched:     map[string][]byte{},
		statusSet:   map[string]map[string]any{},
	}
}

func (f *fakeCluster) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		path := r.URL.Path
		body, _ := io.ReadAll(r.Body)

		switch {
		// List TrstctlControlPlanes.
		case r.Method == http.MethodGet && strings.HasSuffix(path, "/"+tcpPlural):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"apiVersion": tcpAPIGroupVersion, "kind": "TrstctlControlPlaneList", "items": f.tcps,
			})

		// Patch a TrstctlControlPlane status subresource.
		case r.Method == http.MethodPatch && strings.HasSuffix(path, "/status") && strings.Contains(path, "/"+tcpPlural+"/"):
			name := tcpNameFromStatusPath(path)
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			st, _ := obj["status"].(map[string]any)
			f.statusSet[name] = st
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(obj)

		// Get a Deployment (404 when it does not exist).
		case r.Method == http.MethodGet && strings.Contains(path, "/deployments/"):
			name := lastSegment(path)
			dep, ok := f.deployments[name]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(dep)

		// Create a Deployment.
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/deployments"):
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			f.created = append(f.created, obj)
			// Make it live for any subsequent GET in the same test.
			if meta, _ := obj["metadata"].(map[string]any); meta != nil {
				if name, _ := meta["name"].(string); name != "" {
					f.deployments[name] = obj
				}
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(obj)

		// Patch a Deployment.
		case r.Method == http.MethodPatch && strings.Contains(path, "/deployments/"):
			name := lastSegment(path)
			f.patched[name] = body
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"metadata":{"name":"` + name + `"}}`))

		// Get a Lease (404 when no operator has acquired it yet).
		case r.Method == http.MethodGet && strings.Contains(path, "/leases/"):
			name := lastSegment(path)
			lease, ok := f.leases[name]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(lease)

		// Create the leader-election Lease.
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/leases"):
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			meta, _ := obj["metadata"].(map[string]any)
			name, _ := meta["name"].(string)
			if name == "" {
				http.Error(w, "missing lease name", http.StatusBadRequest)
				return
			}
			if _, exists := f.leases[name]; exists {
				http.Error(w, "already exists", http.StatusConflict)
				return
			}
			meta["resourceVersion"] = "1"
			f.leases[name] = obj
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(obj)

		// Patch the leader-election Lease.
		case r.Method == http.MethodPatch && strings.Contains(path, "/leases/"):
			name := lastSegment(path)
			lease, ok := f.leases[name]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			var patch map[string]any
			_ = json.Unmarshal(body, &patch)
			mergeMap(lease, patch)
			if meta, _ := lease["metadata"].(map[string]any); meta != nil {
				f.leasePatches++
				meta["resourceVersion"] = "rv-patched"
			}
			_ = json.NewEncoder(w).Encode(lease)

		default:
			http.Error(w, "unexpected "+r.Method+" "+path, http.StatusNotImplemented)
		}
	})
}

func mergeMap(dst, patch map[string]any) {
	for k, v := range patch {
		pm, pok := v.(map[string]any)
		dm, dok := dst[k].(map[string]any)
		if pok && dok {
			mergeMap(dm, pm)
			continue
		}
		dst[k] = v
	}
}

func tcpNameFromStatusPath(path string) string {
	// .../trstctlcontrolplanes/<name>/status
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return ""
}

func lastSegment(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return parts[len(parts)-1]
}

func tcpObject(name string, replicas int, image string) map[string]any {
	return map[string]any{
		"apiVersion": tcpAPIGroupVersion,
		"kind":       "TrstctlControlPlane",
		"metadata":   map[string]any{"name": name, "namespace": "trstctl-system"},
		"spec":       map[string]any{"replicas": replicas, "image": image},
	}
}

func tcpObjectFullConfig(name string) map[string]any {
	obj := tcpObject(name, 2, "ghcr.io/ctlplne/trstctl:v9")
	obj["spec"] = map[string]any{
		"replicas":   2,
		"image":      "ghcr.io/ctlplne/trstctl:v9",
		"signerMode": "sidecar",
		"postgres": map[string]any{
			"dsnSecret":    "trstctl-postgres",
			"dsnSecretKey": "dsn",
		},
		"nats": map[string]any{
			"url":                 "nats://trstctl-nats:4222",
			"replicas":            3,
			"allowSingleReplica":  false,
			"syncAlways":          true,
			"syncIntervalSeconds": 5,
		},
		"externalKMS": map[string]any{
			"enabled": false,
		},
	}
	return obj
}

func liveDeployment(name string, replicas int, image string) map[string]any {
	configHash := ControlPlaneSpec{Replicas: replicas, Image: image}.desiredConfigHash()
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":            name,
			"namespace":       "trstctl-system",
			"resourceVersion": "100",
			"annotations":     map[string]any{"trstctl.com/config-hash": configHash},
		},
		"spec": map[string]any{
			"replicas": replicas,
			"template": map[string]any{
				"metadata": map[string]any{"annotations": map[string]any{"trstctl.com/config-hash": configHash}},
				"spec": map[string]any{
					"containers": []any{map[string]any{"name": "control-plane", "image": image}},
				},
			},
		},
	}
}

// reconcilerForCluster wires a Reconciler to a fake cluster's httptest server.
func reconcilerForCluster(srv *httptest.Server) *Reconciler {
	return NewReconciler(NewClient(srv.URL, "fake-sa-token", srv.Client()))
}

// TestReconcileCreatesMissingDeployment drives the full reconcile against the
// fake API server: with a TrstctlControlPlane present but NO Deployment, the
// operator must POST a control-plane Deployment that matches the spec
// (replicas+image) and mark the CR status Reconciling. FAILS pre-fix (there was
// no operator at all).
func TestReconcileCreatesMissingDeployment(t *testing.T) {
	f := newFakeCluster()
	f.tcps = []map[string]any{tcpObject("prod", 2, "ghcr.io/ctlplne/trstctl:v9")}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	r := reconcilerForCluster(srv)
	actions, err := r.ReconcileNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if actions["prod"] != ActionCreate {
		t.Fatalf("action for prod = %q, want %q", actions["prod"], ActionCreate)
	}
	if len(f.created) != 1 {
		t.Fatalf("expected exactly one Deployment created, got %d", len(f.created))
	}
	// The created Deployment must encode the spec's desired state.
	created := f.created[0]
	if got := deploymentReplicas(t, created); got != 2 {
		t.Errorf("created Deployment replicas = %d, want 2", got)
	}
	if got := deploymentImage(t, created); got != "ghcr.io/ctlplne/trstctl:v9" {
		t.Errorf("created Deployment image = %q, want the spec image", got)
	}
	if name := deploymentName(t, created); name != "prod-control-plane" {
		t.Errorf("created Deployment name = %q, want prod-control-plane", name)
	}
	// And the operator wrote a phase back to the CR status.
	if f.statusSet["prod"]["phase"] != "Reconciling" {
		t.Errorf("CR status.phase = %v, want Reconciling", f.statusSet["prod"]["phase"])
	}
}

// TestReconcileCreatesFullControlPlaneConfig is the DIST-07 served-path
// acceptance test for the broadened operator: the CRD fields for PostgreSQL,
// NATS, and signer topology must become real pod config in the managed
// Deployment, not dormant schema decorations.
func TestReconcileCreatesFullControlPlaneConfig(t *testing.T) {
	f := newFakeCluster()
	f.tcps = []map[string]any{tcpObjectFullConfig("prod")}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	r := reconcilerForCluster(srv)
	actions, err := r.ReconcileNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if actions["prod"] != ActionCreate {
		t.Fatalf("action for prod = %q, want %q", actions["prod"], ActionCreate)
	}
	if len(f.created) != 1 {
		t.Fatalf("expected one configured Deployment, got %d", len(f.created))
	}
	created := f.created[0]
	env := controlPlaneEnv(t, created)
	if got := envLiteral(env, "TRSTCTL_POSTGRES_MODE"); got != "external" {
		t.Errorf("TRSTCTL_POSTGRES_MODE = %q, want external", got)
	}
	if got := envSecretName(env, "TRSTCTL_POSTGRES_DSN"); got != "trstctl-postgres" {
		t.Errorf("TRSTCTL_POSTGRES_DSN secret = %q, want trstctl-postgres", got)
	}
	if got := envSecretKey(env, "TRSTCTL_POSTGRES_DSN"); got != "dsn" {
		t.Errorf("TRSTCTL_POSTGRES_DSN key = %q, want dsn", got)
	}
	if got := envLiteral(env, "TRSTCTL_NATS_MODE"); got != "external" {
		t.Errorf("TRSTCTL_NATS_MODE = %q, want external", got)
	}
	if got := envLiteral(env, "TRSTCTL_NATS_URL"); got != "nats://trstctl-nats:4222" {
		t.Errorf("TRSTCTL_NATS_URL = %q", got)
	}
	if got := envLiteral(env, "TRSTCTL_NATS_REPLICAS"); got != "3" {
		t.Errorf("TRSTCTL_NATS_REPLICAS = %q, want 3", got)
	}
	if got := envLiteral(env, "TRSTCTL_NATS_SYNC_ALWAYS"); got != "true" {
		t.Errorf("TRSTCTL_NATS_SYNC_ALWAYS = %q, want true", got)
	}
	if got := envLiteral(env, "TRSTCTL_SIGNER_MODE"); got != "external" {
		t.Errorf("TRSTCTL_SIGNER_MODE = %q, want external for sidecar UDS signer", got)
	}
	if got := envLiteral(env, "TRSTCTL_SIGNER_SOCKET"); got != "/run/trstctl/signer.sock" {
		t.Errorf("TRSTCTL_SIGNER_SOCKET = %q, want shared UDS", got)
	}
	if !hasContainer(created, "signer") {
		t.Fatal("full sidecar config should render a signer container")
	}
	for _, volume := range []string{"signer-sock", "signer-keys", "signer-auth", "kek"} {
		if !hasVolume(created, volume) {
			t.Errorf("full sidecar config should render volume %q", volume)
		}
	}
}

// TestReconcilePatchesDriftedDeployment proves the convergence action: when a
// Deployment exists but its replicas/image drifted from the spec, the operator
// PATCHes it back (it does not recreate) and marks the CR Reconciling.
func TestReconcilePatchesDriftedDeployment(t *testing.T) {
	f := newFakeCluster()
	f.tcps = []map[string]any{tcpObject("prod", 3, "ghcr.io/ctlplne/trstctl:NEW")}
	// Live deployment is drifted: 1 replica and an OLD image.
	f.deployments["prod-control-plane"] = liveDeployment("prod-control-plane", 1, "ghcr.io/ctlplne/trstctl:OLD")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	r := reconcilerForCluster(srv)
	actions, err := r.ReconcileNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if actions["prod"] != ActionUpdate {
		t.Fatalf("action = %q, want %q", actions["prod"], ActionUpdate)
	}
	if len(f.created) != 0 {
		t.Errorf("a drifted Deployment must be patched, not recreated; got %d creates", len(f.created))
	}
	patch, ok := f.patched["prod-control-plane"]
	if !ok {
		t.Fatal("operator did not PATCH the drifted Deployment")
	}
	var pj map[string]any
	if err := json.Unmarshal(patch, &pj); err != nil {
		t.Fatalf("patch body is not JSON: %v", err)
	}
	if got := deploymentReplicas(t, pj); got != 3 {
		t.Errorf("patch replicas = %d, want 3", got)
	}
	if got := deploymentImage(t, pj); got != "ghcr.io/ctlplne/trstctl:NEW" {
		t.Errorf("patch image = %q, want the spec image", got)
	}
}

// TestReconcileNoopWhenInSync proves the operator is idempotent and does not
// thrash: a Deployment already matching the spec yields no create and no patch,
// and the CR is marked Ready.
func TestReconcileNoopWhenInSync(t *testing.T) {
	f := newFakeCluster()
	f.tcps = []map[string]any{tcpObject("prod", 2, "ghcr.io/ctlplne/trstctl:v9")}
	f.deployments["prod-control-plane"] = liveDeployment("prod-control-plane", 2, "ghcr.io/ctlplne/trstctl:v9")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	r := reconcilerForCluster(srv)
	actions, err := r.ReconcileNamespace(context.Background(), "trstctl-system")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if actions["prod"] != ActionNone {
		t.Fatalf("action = %q, want %q", actions["prod"], ActionNone)
	}
	if len(f.created) != 0 || len(f.patched) != 0 {
		t.Errorf("in-sync reconcile must be a no-op; creates=%d patches=%d", len(f.created), len(f.patched))
	}
	if f.statusSet["prod"]["phase"] != "Ready" {
		t.Errorf("CR status.phase = %v, want Ready", f.statusSet["prod"]["phase"])
	}
}

// TestLeaderElectionAllowsExactlyOneActiveReplica is the DIST-07 leader election
// acceptance test: when two operator replicas contend for one Lease, only one is
// allowed to reconcile while the lease is fresh; the same leader can renew.
func TestLeaderElectionAllowsExactlyOneActiveReplica(t *testing.T) {
	f := newFakeCluster()
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	client := NewClient(srv.URL, "fake-sa-token", srv.Client())
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	a := NewLeaseElector(client, "trstctl-system", "trstctl-operator", "operator-a", 15*time.Second, clock)
	b := NewLeaseElector(client, "trstctl-system", "trstctl-operator", "operator-b", 15*time.Second, clock)

	leaderA, err := a.TryAcquireOrRenew(context.Background())
	if err != nil {
		t.Fatalf("operator-a acquire: %v", err)
	}
	leaderB, err := b.TryAcquireOrRenew(context.Background())
	if err != nil {
		t.Fatalf("operator-b acquire: %v", err)
	}
	if !leaderA || leaderB {
		t.Fatalf("fresh lease leaders: operator-a=%v operator-b=%v, want exactly operator-a", leaderA, leaderB)
	}

	now = now.Add(5 * time.Second)
	leaderA, err = a.TryAcquireOrRenew(context.Background())
	if err != nil {
		t.Fatalf("operator-a renew: %v", err)
	}
	if !leaderA {
		t.Fatal("current leader could not renew its own lease")
	}
	if f.leasePatches == 0 {
		t.Fatal("leader renewal did not patch the Kubernetes Lease")
	}
}

// --- small typed extractors so the assertions read the real rendered objects ---

func deploymentReplicas(t *testing.T, obj map[string]any) int {
	t.Helper()
	spec, _ := obj["spec"].(map[string]any)
	switch v := spec["replicas"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		t.Fatalf("spec.replicas missing/wrong type: %T", spec["replicas"])
		return 0
	}
}

func deploymentImage(t *testing.T, obj map[string]any) string {
	t.Helper()
	spec, _ := obj["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	pod, _ := tmpl["spec"].(map[string]any)
	conts, _ := pod["containers"].([]any)
	for _, c := range conts {
		m, _ := c.(map[string]any)
		if m["name"] == "control-plane" {
			img, _ := m["image"].(string)
			return img
		}
	}
	if len(conts) > 0 {
		m, _ := conts[0].(map[string]any)
		img, _ := m["image"].(string)
		return img
	}
	t.Fatal("no containers in deployment object")
	return ""
}

func deploymentName(t *testing.T, obj map[string]any) string {
	t.Helper()
	meta, _ := obj["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	return name
}

func controlPlaneEnv(t *testing.T, obj map[string]any) []any {
	t.Helper()
	spec, _ := obj["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	pod, _ := tmpl["spec"].(map[string]any)
	conts, _ := pod["containers"].([]any)
	for _, c := range conts {
		m, _ := c.(map[string]any)
		if m["name"] == "control-plane" {
			env, _ := m["env"].([]any)
			return env
		}
	}
	t.Fatal("no control-plane container")
	return nil
}

func envEntry(env []any, name string) map[string]any {
	for _, e := range env {
		m, _ := e.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	return nil
}

func envLiteral(env []any, name string) string {
	e := envEntry(env, name)
	if e == nil {
		return ""
	}
	v, _ := e["value"].(string)
	return v
}

func envSecretName(env []any, name string) string {
	e := envEntry(env, name)
	if e == nil {
		return ""
	}
	vf, _ := e["valueFrom"].(map[string]any)
	sr, _ := vf["secretKeyRef"].(map[string]any)
	v, _ := sr["name"].(string)
	return v
}

func envSecretKey(env []any, name string) string {
	e := envEntry(env, name)
	if e == nil {
		return ""
	}
	vf, _ := e["valueFrom"].(map[string]any)
	sr, _ := vf["secretKeyRef"].(map[string]any)
	v, _ := sr["key"].(string)
	return v
}

func hasContainer(obj map[string]any, name string) bool {
	spec, _ := obj["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	pod, _ := tmpl["spec"].(map[string]any)
	conts, _ := pod["containers"].([]any)
	for _, c := range conts {
		m, _ := c.(map[string]any)
		if m["name"] == name {
			return true
		}
	}
	return false
}

func hasVolume(obj map[string]any, name string) bool {
	spec, _ := obj["spec"].(map[string]any)
	tmpl, _ := spec["template"].(map[string]any)
	pod, _ := tmpl["spec"].(map[string]any)
	vols, _ := pod["volumes"].([]any)
	for _, v := range vols {
		m, _ := v.(map[string]any)
		if m["name"] == name {
			return true
		}
	}
	return false
}
