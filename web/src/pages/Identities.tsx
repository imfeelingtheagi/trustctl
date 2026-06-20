import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, identityState, type GraphImpact, type Identity, type TransitionTo } from "@/lib/api";
import { approvalRows, type ApprovalQueueRow } from "@/lib/approvalQueue";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DetailDrawer } from "@/components/DetailDrawer";
import { CredentialActivityTimeline } from "@/components/CredentialActivityTimeline";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";

/** action is a lifecycle transition offered for a given state. `to` is bound to the
 * OpenAPI-generated transition enum (TransitionTo), so the UI can never offer (or send)
 * a target the served contract does not accept — drift here fails the build. */
interface Action {
  label: string;
  to: TransitionTo;
}

const lifecycleTargets: TransitionTo[] = ["issued", "deployed", "renewing", "revoked", "retired"];
const identityKinds = [
  "x509_certificate",
  "ssh_certificate",
  "ssh_key",
  "secret",
  "api_key",
  "workload_identity",
] as const satisfies Identity["kind"][];
type KindFilter = "all" | Identity["kind"];
type BulkResult = { id: string; name: string; status: "accepted" | "failed"; message: string };
type BlastRadiusState = {
  error: string | null;
  impact: GraphImpact | null;
  loading: boolean;
  nodeId: string | null;
};

const emptyBlastRadiusState: BlastRadiusState = {
  error: null,
  impact: null,
  loading: false,
  nodeId: null,
};

const kindCopy: Record<Identity["kind"], { title: string; description: string }> = {
  x509_certificate: {
    title: "X.509 certificate identity",
    description: "A TLS or mTLS identity whose lifecycle is backed by certificate issuance, revocation, and expiry evidence.",
  },
  ssh_certificate: {
    title: "SSH certificate identity",
    description: "A short-lived SSH host or user certificate identity controlled by the SSH CA and lifecycle state machine.",
  },
  ssh_key: {
    title: "SSH key identity",
    description: "A standing SSH key identity that should be owned, rotated, and retired like any other non-human credential.",
  },
  secret: {
    title: "Secret identity",
    description: "A password, shared secret, or opaque credential identity tracked separately from certificate inventory.",
  },
  api_key: {
    title: "API key identity",
    description: "An API token or service key identity where ownership, age, and retirement matter more than a certificate chain.",
  },
  workload_identity: {
    title: "Workload identity",
    description: "A service, job, agent, or workload identity that can be issued short-lived credentials instead of storing static secrets.",
  },
};

/** isDestructive reports whether a target state is a destructive transition that must
 * be confirmed before it runs — revoke permanently invalidates the credential, and
 * retire discards it (SURFACE-007). */
function isDestructive(to: TransitionTo): boolean {
  return to === "revoked" || to === "retired";
}

/** errorMessage renders an action error, special-casing a 429 so the user sees a
 * concrete retry hint (Retry-After) instead of a bare failure (SURFACE-007). */
function apiProblemMessage(err: unknown): string {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || err.message;
    } catch {
      return err.body || err.message;
    }
  }
  return err instanceof Error ? err.message : String(err);
}

function errorMessage(err: unknown): string {
  if (err instanceof ApiError && err.isRateLimited) {
    return err.retryAfterSeconds != null
      ? `Rate limited — please retry in ${err.retryAfterSeconds}s.`
      : "Rate limited — please retry shortly.";
  }
  return `Action failed: ${apiProblemMessage(err)}`;
}

/** actionsFor returns the lifecycle actions valid from a state — the UI mirror
 * of the orchestrator's transition table (issue → deploy → renew, revoke, and
 * retire). */
function actionsFor(state: string): Action[] {
  switch (state) {
    case "requested":
      return [{ label: "Issue", to: "issued" }];
    case "issued":
      return [
        { label: "Deploy", to: "deployed" },
        { label: "Revoke", to: "revoked" },
      ];
    case "deployed":
      return [
        { label: "Renew", to: "renewing" },
        { label: "Revoke", to: "revoked" },
      ];
    case "renewing":
      return [{ label: "Revoke", to: "revoked" }];
    case "revoked":
      return [{ label: "Retire", to: "retired" }];
    default:
      return [];
  }
}

function actionForTarget(state: string, target: TransitionTo): Action | undefined {
  return actionsFor(state).find((a) => a.to === target);
}

function terminalMessage(state: string): string | null {
  if (state === "retired") {
    return "Terminal state: retired identities have no valid next transition.";
  }
  if (state === "revoked") {
    return "Terminal trust state: relying parties should no longer accept this identity; only record-retirement cleanup remains.";
  }
  return null;
}

function deliveryEvidence(state: string): string {
  switch (state) {
    case "requested":
      return "Awaiting issue approval or issue request; no downstream delivery yet.";
    case "issued":
      return "Issued. Deploy can be requested; outbox delivery receipt is not served.";
    case "deployed":
      return "Backend state says deployed; connector delivery proof is not served.";
    case "renewing":
      return "Renewal in progress; rotation worker status is not served.";
    case "revoked":
      return "Revoked. OCSP/CRL health needs protocol status before it can be shown here.";
    case "retired":
      return "Terminal retired state; no next lifecycle action.";
    default:
      return "Lifecycle state is served; downstream delivery status is not served.";
  }
}

function transitionNotice(to: TransitionTo): string {
  return `${to} request accepted. Idempotency-Key protects retried submissions from duplicate execution; downstream outbox delivery status is not served yet.`;
}

function deniedKey(id: string, to: TransitionTo): string {
  return `${id}:${to}`;
}

function formatDate(value?: string): string {
  if (!value) return "-";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function displayValue(value: unknown): string {
  if (value == null) return "-";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function stringAttribute(identity: Identity, keys: string[]): string | null {
  for (const key of keys) {
    const value = identity.attributes?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

export function graphNodeIdForIdentity(identity: Identity): string | null {
  const explicit = stringAttribute(identity, ["graph_node_id", "graph_node", "graph_id"]);
  if (explicit) return explicit;

  const credentialID = stringAttribute(identity, ["credential_id", "certificate_id"]);
  if (credentialID) return credentialID.startsWith("cert:") ? credentialID : `cert:${credentialID}`;

  return identity.kind === "x509_certificate" && identity.id ? `cert:${identity.id}` : null;
}

function attributeRows(identity: Identity): Array<[string, string]> {
  return Object.entries(identity.attributes ?? {})
    .slice(0, 8)
    .map(([key, value]) => [key, displayValue(value)]);
}

export function Identities() {
  const [items, setItems] = useState<Identity[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [deniedTransitions, setDeniedTransitions] = useState<Record<string, string>>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Identity | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [transitionReasons, setTransitionReasons] = useState<Record<string, string>>({});
  const [showForm, setShowForm] = useState(false);
  // A destructive transition awaiting explicit confirmation (SURFACE-007). null
  // means no confirmation is pending.
  const [pending, setPending] = useState<{ id: string; name: string; to: TransitionTo; label: string; reason?: string } | null>(null);
  const [pendingConfirmName, setPendingConfirmName] = useState("");
  const [pendingReason, setPendingReason] = useState("");
  const [kindFilter, setKindFilter] = useState<KindFilter>("all");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [bulkConfirmOpen, setBulkConfirmOpen] = useState(false);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkResults, setBulkResults] = useState<BulkResult[]>([]);
  const [pendingImpact, setPendingImpact] = useState<BlastRadiusState>(emptyBlastRadiusState);
  const impactRequestRef = useRef(0);
  const filteredItems = useMemo(
    () => (items ?? []).filter((identity) => kindFilter === "all" || identity.kind === kindFilter),
    [items, kindFilter],
  );
  const selectedRows = useMemo(
    () => filteredItems.filter((identity) => selectedIds.has(identity.id)),
    [filteredItems, selectedIds],
  );

  const load = useCallback(async () => {
    try {
      setItems(await api.identities());
      setError(null);
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const loadDetail = useCallback(async (id: string) => {
    setDetailLoading(true);
    setDetailError(null);
    try {
      setDetail(await api.getIdentity(id));
    } catch (err) {
      setDetailError(`Could not load identity detail: ${apiProblemMessage(err)}`);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  function openDetail(identity: Identity) {
    setSelectedId(identity.id);
    setDetail(identity);
    void loadDetail(identity.id);
  }

  async function act(id: string, to: TransitionTo, reason?: string) {
    setBusyId(id);
    setError(null);
    setNotice(null);
    try {
      await api.transitionIdentity(id, to, reason?.trim() || `${to} via UI`);
      await load();
      if (selectedId === id) {
        await loadDetail(id);
      }
      setNotice(transitionNotice(to));
      setDeniedTransitions((current) => {
        const next = { ...current };
        delete next[deniedKey(id, to)];
        return next;
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setDeniedTransitions((current) => ({ ...current, [deniedKey(id, to)]: apiProblemMessage(err) }));
      }
      setError(errorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  /** request runs a transition immediately, EXCEPT a destructive one (revoke/retire)
   * which is first parked in `pending` so the user must confirm it in a dialog that
   * names the credential (SURFACE-007). */
  function clearPending() {
    impactRequestRef.current += 1;
    setPending(null);
    setPendingConfirmName("");
    setPendingImpact(emptyBlastRadiusState);
  }

  function loadBlastRadius(identity: Identity) {
    const nodeId = graphNodeIdForIdentity(identity);
    const requestID = impactRequestRef.current + 1;
    impactRequestRef.current = requestID;

    if (!nodeId) {
      setPendingImpact({
        nodeId: null,
        impact: null,
        loading: false,
        error: "Blast-radius impact unavailable: no served graph node mapping for this identity.",
      });
      return;
    }

    setPendingImpact({ nodeId, impact: null, loading: true, error: null });
    api
      .graphBlastRadius(nodeId)
      .then((impact) => {
        if (impactRequestRef.current === requestID) {
          setPendingImpact({ nodeId, impact, loading: false, error: null });
        }
      })
      .catch((err) => {
        if (impactRequestRef.current === requestID) {
          setPendingImpact({
            nodeId,
            impact: null,
            loading: false,
            error: `Blast-radius impact unavailable: ${apiProblemMessage(err)}`,
          });
        }
      });
  }

  function request(identity: Identity, to: TransitionTo, label: string, reason?: string) {
    if (isDestructive(to)) {
      setPendingConfirmName("");
      setPendingReason(reason?.trim() || (to === "revoked" ? "operator requested revocation" : "operator requested retirement"));
      setPending({ id: identity.id, name: identity.name, to, label, reason });
      loadBlastRadius(identity);
      return;
    }
    void act(identity.id, to, reason);
  }

  async function runBulkRevoke() {
    const rows = selectedRows;
    setBulkBusy(true);
    setBulkResults([]);
    const results: BulkResult[] = [];
    for (const identity of rows) {
      if (!actionForTarget(identityState(identity), "revoked")) {
        results.push({
          id: identity.id,
          name: identity.name,
          status: "failed",
          message: "revoke is not valid from this lifecycle state",
        });
        continue;
      }
      try {
        await api.transitionIdentity(identity.id, "revoked", "bulk revoke via UI");
        results.push({ id: identity.id, name: identity.name, status: "accepted", message: "accepted" });
      } catch (err) {
        results.push({ id: identity.id, name: identity.name, status: "failed", message: apiProblemMessage(err) });
      }
    }
    setBulkResults(results);
    setSelectedIds(new Set());
    setBulkConfirmOpen(false);
    setBulkBusy(false);
    await load();
  }

  const identityColumns = useMemo<Array<DataGridColumn<Identity>>>(
    () => [
      {
        id: "name",
        header: "Name",
        sortable: true,
        cell: (identity) => <span className="font-medium">{identity.name}</span>,
      },
      {
        id: "kind",
        header: "Kind",
        cell: (identity) => identity.kind ?? "unknown",
      },
      {
        id: "owner",
        header: "Owner",
        cell: (identity) => identity.owner_id || "not served",
      },
      {
        id: "state",
        header: "State",
        cell: (identity) => <StatusBadge vocabulary="lifecycle" value={identityState(identity)} />,
      },
      {
        id: "delivery",
        header: "Delivery evidence",
        cell: (identity) => (
          <span className="text-muted-foreground">{deliveryEvidence(identityState(identity))}</span>
        ),
      },
      {
        id: "actions",
        header: "Actions",
        cell: (identity) => {
          const state = identityState(identity);
          const actions = actionsFor(state);
          return (
            <div className="flex flex-wrap gap-2">
              {actions.map((a) => (
                <div key={a.to} className="space-y-1">
                  <Button
                    type="button"
                    size="sm"
                    variant={isDestructive(a.to) ? "outline" : "default"}
                    disabled={busyId === identity.id || Boolean(deniedTransitions[deniedKey(identity.id, a.to)])}
                    aria-describedby={
                      deniedTransitions[deniedKey(identity.id, a.to)] ? `denied-${identity.id}-${a.to}` : undefined
                    }
                    onClick={() => request(identity, a.to, a.label)}
                  >
                    {a.label}
                  </Button>
                  {deniedTransitions[deniedKey(identity.id, a.to)] && (
                    <p
                      id={`denied-${identity.id}-${a.to}`}
                      className="max-w-xs text-xs text-amber-700 dark:text-amber-300"
                    >
                      {deniedTransitions[deniedKey(identity.id, a.to)]}
                    </p>
                  )}
                </div>
              ))}
              {actions.length === 0 && <span className="text-xs text-muted-foreground">—</span>}
            </div>
          );
        },
      },
    ],
    [busyId, deniedTransitions],
  );

  return (
    <section aria-labelledby="identities-heading">
      <div className="mb-4 flex items-center justify-between">
        <h1 id="identities-heading" className="text-2xl font-semibold">
          Identities
        </h1>
        <Button type="button" onClick={() => setShowForm((s) => !s)}>
          New identity
        </Button>
      </div>

      {showForm && (
        <NewIdentityForm
          onDone={() => {
            setShowForm(false);
            void load();
          }}
        />
      )}

      <section aria-labelledby="issuance-guardrails" className="mb-4 border-y border-border py-4">
        <h2 id="issuance-guardrails" className="text-sm font-semibold">
          Issuance guardrails
        </h2>
        <div className="mt-2 grid gap-2 text-sm text-muted-foreground md:grid-cols-3">
          <p>
            Issue and revoke are privileged signing actions. The backend enforces RA
            separation, dual control, and policy before the signer is asked to act.
          </p>
          <p>
            A request-only principal cannot self-issue, and self-approval is denied.
            Use the approval action with a distinct approver, then retry the transition.
          </p>
          <p>
            Every lifecycle mutation carries an Idempotency-Key. If the same request is
            retried by the network, the backend returns the original result.
          </p>
        </div>
      </section>

      <div className="mb-4">
        <UnavailableState title="Outbox delivery status not served yet">
          Deploy, renew, revoke, and connector side effects are queued server-side, but
          pending, processing, delivered, failed, and replayed delivery states do not
          have a served read API yet.
        </UnavailableState>
      </div>

      <LifecycleAutomationDisclosure />

      <RevocationPublicationPanel />

      {notice && (
        <p role="status" className="mb-3 text-sm text-green-700 dark:text-green-400">
          {notice}
        </p>
      )}

      {pending && (
        <div
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="confirm-title"
          aria-describedby="confirm-desc"
          className="mb-4 rounded-md border border-red-300 bg-red-50 p-4 dark:border-red-800 dark:bg-red-950"
        >
          <h2 id="confirm-title" className="text-sm font-semibold text-red-700 dark:text-red-300">
            {pending.label} “{pending.name}”?
          </h2>
          <p id="confirm-desc" className="mt-1 text-sm text-red-700 dark:text-red-300">
            {pending.to === "revoked"
              ? `Revoking “${pending.name}” permanently invalidates the credential; relying parties will stop trusting it. This cannot be undone.`
              : `Retiring “${pending.name}” discards the credential record. This cannot be undone.`}
          </p>
          <BlastRadiusImpactPanel state={pendingImpact} />
          <div className="mt-3 grid gap-3">
            <label className="block text-sm font-medium text-red-800 dark:text-red-200" htmlFor="destructive-confirm-name">
              Type credential name to confirm
            </label>
            <input
              id="destructive-confirm-name"
              value={pendingConfirmName}
              onChange={(e) => setPendingConfirmName(e.target.value)}
              className="rounded-md border border-red-300 bg-background px-3 py-2 text-sm text-foreground"
              placeholder={pending.name}
            />
            <label className="block text-sm font-medium text-red-800 dark:text-red-200" htmlFor="destructive-reason">
              {pending.to === "revoked" ? "Revocation reason" : "Transition reason"}
            </label>
            <textarea
              id="destructive-reason"
              value={pendingReason}
              onChange={(e) => setPendingReason(e.target.value)}
              className="min-h-20 rounded-md border border-red-300 bg-background px-3 py-2 text-sm text-foreground"
              placeholder={pending.to === "revoked" ? "e.g. key compromise CAB-1234" : "e.g. record cleanup approved in CAB-1234"}
            />
          </div>
          <div className="mt-3 flex gap-2">
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="border-red-400 text-red-700 hover:bg-red-100 dark:text-red-300"
              disabled={busyId === pending.id || pendingConfirmName.trim() !== pending.name}
              onClick={() => {
                const p = pending;
                clearPending();
                void act(p.id, p.to, pendingReason);
              }}
            >
              {`Yes, ${pending.label.toLowerCase()}`}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={clearPending}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}

      {selectedRows.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-3 rounded-md border border-border bg-muted px-3 py-2 text-sm">
          <span className="font-medium">{selectedRows.length} selected</span>
          <Button type="button" size="sm" variant="outline" onClick={() => setBulkConfirmOpen(true)}>
            Bulk revoke selected
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={() => setSelectedIds(new Set())}>
            Clear selection
          </Button>
        </div>
      )}

      {bulkConfirmOpen && (
        <div
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="bulk-revoke-title"
          aria-describedby="bulk-revoke-desc"
          className="mb-4 rounded-md border border-red-300 bg-red-50 p-4 text-sm dark:border-red-800 dark:bg-red-950"
        >
          <h2 id="bulk-revoke-title" className="font-semibold text-red-700 dark:text-red-300">
            Revoke {selectedRows.length} selected identities?
          </h2>
          <p id="bulk-revoke-desc" className="mt-1 text-red-700 dark:text-red-300">
            This sends one idempotent revoke request per selected identity and reports accepted or failed for each item. Connector and downstream delivery still complete asynchronously through the outbox.
          </p>
          <div className="mt-3 flex gap-2">
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="border-red-400 text-red-700 hover:bg-red-100 dark:text-red-300"
              disabled={bulkBusy}
              onClick={() => void runBulkRevoke()}
            >
              Confirm bulk revoke
            </Button>
            <Button type="button" size="sm" variant="ghost" disabled={bulkBusy} onClick={() => setBulkConfirmOpen(false)}>
              Cancel
            </Button>
          </div>
        </div>
      )}

      {bulkResults.length > 0 && (
        <div role="status" className="mb-3 rounded-md border border-border p-3 text-sm">
          <p className="font-medium">
            Bulk revoke results: accepted {bulkResults.filter((result) => result.status === "accepted").length}; failed{" "}
            {bulkResults.filter((result) => result.status === "failed").length}
          </p>
          <ul className="mt-2 space-y-1">
            {bulkResults.map((result) => (
              <li key={result.id}>
                {result.name} {result.status}
                {result.status === "failed" ? `: ${result.message}` : ""}
              </li>
            ))}
          </ul>
        </div>
      )}

      {!items && !error && <LoadingState>Loading identities...</LoadingState>}
      {error && <ErrorState title="Identity action failed">{error}</ErrorState>}

      {items && items.length === 0 && !showForm && (
        <EmptyState
          title="No identities yet"
          ctaTo="/wizard"
          ctaLabel="Set up your first certificate"
        >
          Issue your first certificate to start tracking and rotating credentials.
        </EmptyState>
      )}

      {items && items.length > 0 && (
        <PendingApprovalSummary rows={approvalRows(items)} />
      )}

      {items && items.length > 0 && (
        <div id="manual-lifecycle-transitions" className="space-y-3">
          <label className="grid max-w-xs gap-1 text-sm font-medium" htmlFor="identity-kind-filter">
            Kind
            <select
              id="identity-kind-filter"
              value={kindFilter}
              onChange={(event) => setKindFilter(event.target.value as KindFilter)}
              className="rounded-md border border-border bg-background px-3 py-2"
            >
              <option value="all">All kinds</option>
              {identityKinds.map((kind) => (
                <option key={kind} value={kind}>
                  {kind}
                </option>
              ))}
            </select>
          </label>
          <DataGrid
            ariaLabel="Credential identities and their lifecycle state"
            rows={filteredItems}
            columns={identityColumns}
            getRowId={(identity) => identity.id}
            selection={{
              selectedIds,
              onSelectedIdsChange: setSelectedIds,
              getRowLabel: (identity) => identity.name,
            }}
            state={filteredItems.length === 0 ? "empty" : "ready"}
            stateTitle="No identities match this kind"
            stateMessage="Choose another identity kind or clear the filter."
            onRowOpen={openDetail}
            rowActionLabel={() => "View details"}
          />
        </div>
      )}

      <DetailDrawer
        open={!!selectedId}
        title="Identity detail"
        description={detail ? `${detail.name} from the served identity detail API.` : "Served identity detail."}
        onClose={() => setSelectedId(null)}
      >
        <IdentityDetailPanel
          identity={detail}
          loading={detailLoading}
          error={detailError}
          busy={busyId === selectedId}
          deniedTransitions={deniedTransitions}
          reason={selectedId ? transitionReasons[selectedId] ?? "" : ""}
          onReasonChange={(value) => {
            if (!selectedId) return;
            setTransitionReasons((current) => ({ ...current, [selectedId]: value }))
          }}
          onTransition={(to, label) => {
            if (!detail) return;
            request(detail, to, label, transitionReasons[detail.id]);
          }}
        />
      </DetailDrawer>
    </section>
  );
}

function BlastRadiusImpactPanel({ state }: { state: BlastRadiusState }) {
  if (state.loading) {
    return (
      <div className="mt-3 rounded-md border border-red-200 bg-background/80 p-3 text-sm text-red-700 dark:border-red-900 dark:text-red-300">
        Loading blast-radius impact from served graph...
      </div>
    );
  }

  if (state.error) {
    return (
      <div className="mt-3 rounded-md border border-red-200 bg-background/80 p-3 text-sm text-red-700 dark:border-red-900 dark:text-red-300">
        {state.error}
      </div>
    );
  }

  if (!state.impact) return null;

  const affected = state.impact.affected.length;
  const byKind = Object.entries(state.impact.by_kind ?? {});
  return (
    <section
      aria-labelledby="destructive-blast-radius-heading"
      className="mt-3 rounded-md border border-red-200 bg-background/80 p-3 text-sm text-red-700 dark:border-red-900 dark:text-red-300"
    >
      <h3 id="destructive-blast-radius-heading" className="font-semibold">
        Blast-radius impact
      </h3>
      <p className="mt-1">
        Served graph node <span className="font-mono text-xs">{state.nodeId}</span> reports {affected} downstream
        affected node{affected === 1 ? "" : "s"} before this destructive action.
      </p>
      {byKind.length > 0 && (
        <dl className="mt-2 grid gap-2 sm:grid-cols-2">
          {byKind.map(([kind, value]) => (
            <div key={kind} className="rounded-md border border-red-100 px-2 py-1 dark:border-red-900">
              <dt className="font-medium">{kind}</dt>
              <dd>{displayValue(value)}</dd>
            </div>
          ))}
        </dl>
      )}
    </section>
  );
}

function LifecycleAutomationDisclosure() {
  const previewRows = [
    ["Renew before", "Preview only: schedule window is not served"],
    ["Alert before", "Preview only: notification timing is not served"],
    ["Dry run", "Preview only: no served dry-run endpoint"],
    ["Rollback", "Preview only: rollback status needs outbox delivery state"],
  ];
  return (
    <section aria-labelledby="lifecycle-automation-heading" className="mb-4 border-y border-border py-4">
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_24rem]">
        <div>
          <h2 id="lifecycle-automation-heading" className="text-sm font-semibold">
            Lifecycle automation
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            Renewal is manual today. Auto-renewal, rotation schedules, pending runs, dry-run results, and rollback evidence need `BACKEND-LIFECYCLE-AUTOMATION` plus `BACKEND-OUTBOX-STATUS`.
          </p>
          <a className="mt-3 inline-flex text-sm font-medium text-primary underline" href="#manual-lifecycle-transitions">
            Use manual lifecycle transitions
          </a>
        </div>
        <div className="rounded-md border border-border p-3 text-sm">
          <p className="font-medium">Automation layout preview</p>
          <dl className="mt-2 grid gap-2">
            {previewRows.map(([label, value]) => (
              <div key={label} className="grid grid-cols-[8rem_minmax(0,1fr)] gap-2">
                <dt className="text-muted-foreground">{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>
    </section>
  );
}

function PendingApprovalSummary({ rows }: { rows: ApprovalQueueRow[] }) {
  return (
    <section aria-labelledby="jit-queue-heading" className="mb-4 border-y border-border py-4">
      <div className="mb-3">
        <h2 id="jit-queue-heading" className="text-sm font-semibold">
          JIT approvals moved to the inbox
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Requested identities are summarized here, but approval decisions now happen in the dedicated inbox so request and approve controls are not co-located for one operator.
        </p>
        <Link className="mt-2 inline-flex text-sm font-medium text-primary underline" to="/approvals">
          Open approvals inbox
        </Link>
      </div>
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">No pending served approval actions.</p>
      ) : (
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[48rem] text-left text-sm">
            <caption className="sr-only">Pending JIT approval requests</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Credential</th>
                <th scope="col" className="py-2 pr-4 font-medium">Requester</th>
                <th scope="col" className="py-2 pr-4 font-medium">Action</th>
                <th scope="col" className="py-2 pr-4 font-medium">Approvals count</th>
                <th scope="col" className="py-2 pr-4 font-medium">Time-bound grant</th>
                <th scope="col" className="py-2 pr-3 font-medium">Decision surface</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={`${row.identity.id}:${row.action}`} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4">{`JIT ${row.identity.name}`}</td>
                  <td className="py-2 pr-4">{row.requester}</td>
                  <td className="py-2 pr-4">{row.action}</td>
                  <td className="py-2 pr-4">{row.approvals}</td>
                  <td className="py-2 pr-4">{row.grantExpiresAt}</td>
                  <td className="py-2 pr-3">
                    <Link className="text-primary underline" to="/approvals">
                      Review in approvals
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function RevocationPublicationPanel() {
  return (
    <section aria-labelledby="revocation-publication-heading" className="mb-4 border-y border-border py-4">
      <h2 id="revocation-publication-heading" className="text-sm font-semibold">
        Revocation publication
      </h2>
      <div className="mt-2 grid gap-3 text-sm text-muted-foreground md:grid-cols-3">
        <p>
          Revoked X.509 certificates are published to the served public OCSP and CRL surfaces after the backend records the lifecycle transition.
        </p>
        <p>
          OCSP: <code className="rounded bg-muted px-1 font-mono text-xs">/ocsp/{"{tenant}"}</code>
          <br />
          CRL: <code className="rounded bg-muted px-1 font-mono text-xs">/crl/{"{tenant}"}</code>
        </p>
        <p>
          Live propagation health is not served yet. Freshness, scheduler, and responder health need `BACKEND-PROTOCOL-STATUS`.
        </p>
      </div>
    </section>
  );
}

function IdentityDetailPanel({
  identity,
  loading,
  error,
  busy,
  deniedTransitions,
  reason,
  onReasonChange,
  onTransition,
}: {
  identity: Identity | null;
  loading: boolean;
  error: string | null;
  busy: boolean;
  deniedTransitions: Record<string, string>;
  reason: string;
  onReasonChange: (value: string) => void;
  onTransition: (to: TransitionTo, label: string) => void;
}) {
  const state = identity ? identityState(identity) : "";
  const kind = identity?.kind ? kindCopy[identity.kind] : null;
  const terminal = terminalMessage(state);
  const rows = identity ? attributeRows(identity) : [];

  return (
    <section aria-labelledby="identity-detail-content-heading" className="text-sm">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          <p className="text-xs font-medium uppercase text-muted-foreground">Served identity detail</p>
          <h2 id="identity-detail-content-heading" className="text-lg font-semibold">
            Detail fields
          </h2>
        </div>
        {loading && <p role="status">Loading identity detail...</p>}
      </div>

      {error && (
        <p role="alert" className="mb-3 text-sm text-red-600 dark:text-red-400">
          {error}
        </p>
      )}

      {identity && (
        <>
          <section aria-labelledby="identity-kind-heading" className="mb-4 rounded-md border border-border p-3">
            <h3 id="identity-kind-heading" className="font-semibold">
              {kind?.title ?? "Identity"}
            </h3>
            <p className="mt-1 text-muted-foreground">
              {kind?.description ?? "A served non-human identity bound to this tenant."}
            </p>
            {terminal && (
              <p className="mt-2 rounded-md bg-muted px-3 py-2 text-xs font-medium text-foreground">
                {terminal}
              </p>
            )}
          </section>

          <dl className="grid gap-3 md:grid-cols-2">
            <div>
              <dt className="font-medium text-muted-foreground">Name</dt>
              <dd>{identity.name}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Status</dt>
              <dd>{state || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Kind</dt>
              <dd>{identity.kind}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Not after</dt>
              <dd>{formatDate(identity.not_after)}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Not before</dt>
              <dd>{formatDate(identity.not_before)}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Owner</dt>
              <dd>
                <a className="text-primary underline" href={`/owners?owner=${encodeURIComponent(identity.owner_id)}`}>
                  Owner {identity.owner_id}
                </a>
              </dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Issuer</dt>
              <dd>
                {identity.issuer_id ? (
                  <a className="text-primary underline" href={`/coverage?feature=F5&issuer=${encodeURIComponent(identity.issuer_id)}`}>
                    Issuer {identity.issuer_id}
                  </a>
                ) : (
                  "No issuer bound"
                )}
              </dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Identity ID</dt>
              <dd className="break-all font-mono text-xs">{identity.id}</dd>
            </div>
          </dl>

          <section aria-labelledby="identity-attributes-heading" className="mt-4">
            <h3 id="identity-attributes-heading" className="font-semibold">
              Kind attributes
            </h3>
            {rows.length > 0 ? (
              <dl className="mt-2 grid gap-2 md:grid-cols-2">
                {rows.map(([key, value]) => (
                  <div key={key}>
                    <dt className="font-medium text-muted-foreground">{key}</dt>
                    <dd className="break-all font-mono text-xs">{value}</dd>
                  </div>
                ))}
              </dl>
            ) : (
              <p className="mt-1 text-muted-foreground">
                No extra kind attributes were returned by the served detail endpoint.
              </p>
            )}
          </section>

          <CredentialActivityTimeline credentialLabel={identity.name} />

          <section aria-labelledby="identity-lifecycle-heading" className="mt-5 border-t border-border pt-4">
            <h3 id="identity-lifecycle-heading" className="font-semibold">
              Lifecycle state machine
            </h3>
            <p className="mt-1 text-muted-foreground">
              Only valid next states are enabled. Disabled targets are not sent to the backend.
            </p>
            <label htmlFor="transition-reason" className="mt-3 block text-sm font-medium">
              Transition reason
            </label>
            <textarea
              id="transition-reason"
              value={reason}
              onChange={(e) => onReasonChange(e.target.value)}
              className="mt-1 min-h-20 w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
              placeholder="e.g. change approved in CAB-1234"
            />
            <div className="mt-3 flex flex-wrap gap-2">
              {lifecycleTargets.map((target) => {
                const action = actionForTarget(state, target);
                const denied = deniedTransitions[deniedKey(identity.id, target)];
                const disabled = busy || !action || Boolean(denied);
                const reasonId = `state-machine-${identity.id}-${target}-reason`;
                return (
                  <div key={target} className="max-w-xs space-y-1">
                    <Button
                      type="button"
                      size="sm"
                      variant={isDestructive(target) ? "outline" : "default"}
                      disabled={disabled}
                      aria-describedby={reasonId}
                      onClick={() => action && onTransition(target, action.label)}
                    >
                      Move to {target}
                    </Button>
                    <p id={reasonId} className="text-xs text-muted-foreground">
                      {denied || (action ? `Valid from ${state}.` : target === state ? "Already in this state." : `Invalid from ${state || "unknown"}.`)}
                    </p>
                  </div>
                );
              })}
            </div>
          </section>
        </>
      )}
    </section>
  );
}

function NewIdentityForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.issueCertificate({ name: name.trim() || "new-service" });
      onDone();
    } catch (err) {
      setError(`Could not issue: ${String(err)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="mb-4 flex items-end gap-3 rounded-md border border-border p-4">
      <div className="flex-1 space-y-1">
        <label htmlFor="new-identity-name" className="block text-sm font-medium">
          Service name
        </label>
        <input
          id="new-identity-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
          placeholder="e.g. payments-api"
        />
      </div>
      <Button type="submit" disabled={busy}>
        Issue
      </Button>
      {error && (
        <p role="alert" className="text-sm text-red-600 dark:text-red-400">
          {error}
        </p>
      )}
    </form>
  );
}
