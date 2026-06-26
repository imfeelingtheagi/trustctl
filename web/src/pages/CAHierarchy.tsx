import { useEffect, useMemo, useState } from "react";
import { FileKey2, KeyRound, RefreshCw, ShieldCheck } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { api, ApiError, type CACeremonyStartRequest, type CAKeyCeremony, type Issuer, type ManagedKey } from "@/lib/api";

type Notice = { kind: "permission" | "error"; message: string };

const rootCeremonyRequest: CACeremonyStartRequest = {
  operation: "create_root",
  threshold: 2,
  spec: {
    common_name: "Trust Root CA",
    max_path_len: 1,
    signature_algorithm: "ECDSA-P256",
    ttl_seconds: 315_360_000,
  },
};

const managedKeyRequest = { algorithm: "ECDSA-P256" };

export function CAHierarchy() {
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [ceremony, setCeremony] = useState<CAKeyCeremony | null>(null);
  const [ceremonyBusy, setCeremonyBusy] = useState(false);
  const [ceremonyError, setCeremonyError] = useState<string | null>(null);
  const [managedKey, setManagedKey] = useState<ManagedKey | null>(null);
  const [keyBusy, setKeyBusy] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setNotice(null);
    try {
      setIssuers(await api.issuers());
    } catch (err) {
      setIssuers([]);
      setNotice(noticeForError(err, "Could not load issuers"));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  const sortedIssuers = useMemo(() => [...issuers].sort((a, b) => a.name.localeCompare(b.name)), [issuers]);

  async function startRootCeremony() {
    setCeremonyBusy(true);
    setCeremonyError(null);
    try {
      setCeremony(await api.createCACeremony(rootCeremonyRequest));
    } catch (err) {
      setCeremonyError(errorText(err, "Could not start ceremony"));
    } finally {
      setCeremonyBusy(false);
    }
  }

  async function approveCeremony(id: string) {
    setCeremonyBusy(true);
    setCeremonyError(null);
    try {
      setCeremony(await api.approveCACeremony(id));
    } catch (err) {
      setCeremonyError(errorText(err, "Could not approve ceremony"));
    } finally {
      setCeremonyBusy(false);
    }
  }

  async function generateManagedKey() {
    setKeyBusy(true);
    setKeyError(null);
    try {
      setManagedKey(await api.generateManagedKey(managedKeyRequest));
    } catch (err) {
      setKeyError(errorText(err, "Could not generate managed key"));
    } finally {
      setKeyBusy(false);
    }
  }

  async function runManagedKeyAction(action: "rotate" | "revoke" | "zeroize", keyId: string) {
    setKeyBusy(true);
    setKeyError(null);
    try {
      const next =
        action === "rotate"
          ? await api.rotateManagedKey(keyId)
          : action === "revoke"
            ? await api.revokeManagedKey(keyId)
            : await api.zeroizeManagedKey(keyId);
      setManagedKey(next);
    } catch (err) {
      setKeyError(errorText(err, `Could not ${action} managed key`));
    } finally {
      setKeyBusy(false);
    }
  }

  return (
    <section aria-labelledby="ca-heading" className="grid gap-6">
      <PageHeader
        titleId="ca-heading"
        title="CA hierarchy"
        description="Root and intermediate CA hierarchy with issuer metadata, quorum approval ceremonies, and managed-key custody actions."
        actions={
          <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      <section aria-labelledby="issuer-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <ShieldCheck className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="issuer-heading" className="text-title font-semibold">
              Issuer visibility
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              This view shows issuer name, kind, public key, custody boundary, and chain metadata. The ceremony and managed-key panels below drive the
              corresponding protected workflows.
            </p>
          </div>
        </div>
        {loading && <LoadingState>Loading issuers...</LoadingState>}
        {renderNotice(notice)}
        {!loading && !notice && sortedIssuers.length === 0 && (
          <EmptyState title="No issuers yet">Create issuers before they appear in this hierarchy view.</EmptyState>
        )}
        {!loading && !notice && sortedIssuers.length > 0 && <IssuerTable issuers={sortedIssuers} />}
      </section>

      <section aria-labelledby="ceremony-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <FileKey2 className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="ceremony-heading" className="text-title font-semibold">
              CA key ceremony
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              Start a root CA ceremony, then record a second custodian approval before using the ceremony for a signer-backed authority action.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" onClick={() => void startRootCeremony()} disabled={ceremonyBusy}>
            Start root ceremony
          </Button>
          <span className="text-sm text-muted-foreground">Default request: Trust Root CA, 2 approvals, ECDSA-P256.</span>
        </div>
        {ceremonyError && <ErrorState title="Ceremony action failed">{ceremonyError}</ErrorState>}
        {ceremony ? (
          <CeremonyPanel ceremony={ceremony} busy={ceremonyBusy} onApprove={(id) => void approveCeremony(id)} />
        ) : (
          <EmptyState title="No ceremony loaded">Start a ceremony to see its purpose, approval threshold, and status.</EmptyState>
        )}
      </section>

      <section aria-labelledby="custody-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <KeyRound className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="custody-heading" className="text-title font-semibold">
              Managed key custody
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              Private key bytes never enter the browser. This panel shows returned key metadata and drives custody actions by key id.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" onClick={() => void generateManagedKey()} disabled={keyBusy}>
            Generate managed key
          </Button>
          <span className="text-sm text-muted-foreground">Default algorithm: ECDSA-P256.</span>
        </div>
        {keyError && <ErrorState title="Managed-key action failed">{keyError}</ErrorState>}
        {managedKey ? (
          <ManagedKeyPanel
            managedKey={managedKey}
            busy={keyBusy}
            onAction={(action, keyId) => void runManagedKeyAction(action, keyId)}
          />
        ) : (
          <EmptyState title="No managed key loaded">Generate a managed key to inspect its public metadata and lifecycle state.</EmptyState>
        )}
      </section>
    </section>
  );
}

function CeremonyPanel({ busy, ceremony, onApprove }: { busy: boolean; ceremony: CAKeyCeremony; onApprove: (id: string) => void }) {
  const complete = ceremony.approvals >= ceremony.threshold || ceremony.status === "approved";
  return (
    <section aria-labelledby="active-ceremony-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="active-ceremony-heading" className="text-title font-semibold">
            Active ceremony
          </h3>
          <p className="mt-1 font-mono text-xs">{ceremony.id}</p>
        </div>
        <Button type="button" variant="outline" disabled={busy || complete} onClick={() => onApprove(ceremony.id)} aria-label={`Approve ceremony ${ceremony.id}`}>
          Approve
        </Button>
      </div>
      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <KeyValue label="Purpose" value={ceremony.purpose} mono />
        <KeyValue label="Approvals" value={`${ceremony.approvals} / ${ceremony.threshold} approvals`} />
        <KeyValue label="Status" value={ceremony.status} />
        <KeyValue label="Opened by" value={ceremony.opener || "-"} />
      </dl>
    </section>
  );
}

function ManagedKeyPanel({
  busy,
  managedKey,
  onAction,
}: {
  busy: boolean;
  managedKey: ManagedKey;
  onAction: (action: "rotate" | "revoke" | "zeroize", keyId: string) => void;
}) {
  return (
    <section aria-labelledby="managed-key-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="managed-key-heading" className="text-title font-semibold">
            Managed key
          </h3>
          <p className="mt-1 font-mono text-xs">{managedKey.key_id}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onAction("rotate", managedKey.key_id)} aria-label={`Rotate key ${managedKey.key_id}`}>
            Rotate
          </Button>
          <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onAction("revoke", managedKey.key_id)} aria-label={`Revoke key ${managedKey.key_id}`}>
            Revoke
          </Button>
          <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onAction("zeroize", managedKey.key_id)} aria-label={`Zeroize key ${managedKey.key_id}`}>
            Zeroize
          </Button>
        </div>
      </div>
      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <KeyValue label="Algorithm" value={managedKey.algorithm} />
        <KeyValue label="Version" value={`Version ${managedKey.version}`} />
        <KeyValue label="State" value={managedKey.state} />
        <KeyValue label="Public DER" value={managedKey.public_der ? `${managedKey.public_der.length} bytes` : "-"} />
      </dl>
    </section>
  );
}

function KeyValue({ label, mono = false, value }: { label: string; mono?: boolean; value: string }) {
  return (
    <div>
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "font-medium"}>{value}</dd>
    </div>
  );
}

function IssuerTable({ issuers }: { issuers: Issuer[] }) {
  return (
    <div className="ui-panel overflow-x-auto">
      <table className="ui-table min-w-[52rem]">
        <caption className="sr-only">Issuer list</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Kind</th>
            <th scope="col">Internal</th>
            <th scope="col">Chain</th>
            <th scope="col">Public key</th>
            <th scope="col">Certificates</th>
          </tr>
        </thead>
        <tbody>
          {issuers.map((issuer) => (
            <tr key={issuer.id} className="align-top">
              <td className="font-medium">{issuer.name}</td>
              <td>{issuer.kind}</td>
              <td>{issuer.internal ? "internal" : "external"}</td>
              <td>{issuer.chain?.length ? issuer.chain.join(" -> ") : "-"}</td>
              <td className="max-w-sm break-all font-mono text-xs">{issuer.public_key || "-"}</td>
              <td>
                <a className="text-brand-accent underline" href={`/certificates?issuer=${encodeURIComponent(issuer.id)}`}>
                  Certificates for {issuer.name}
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function renderNotice(notice: Notice | null) {
  if (!notice) return null;
  if (notice.kind === "permission") {
    return <PermissionDeniedState>{notice.message}</PermissionDeniedState>;
  }
  return <ErrorState title="Issuer metadata unavailable">{notice.message}</ErrorState>;
}

function errorText(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || fallback;
    } catch {
      return err.body || fallback;
    }
  }
  return err instanceof Error ? err.message : fallback;
}

function noticeForError(err: unknown, fallback: string): Notice {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return {
        kind: err.status === 403 ? "permission" : "error",
        message: problem.detail || problem.title || fallback,
      };
    } catch {
      return { kind: err.status === 403 ? "permission" : "error", message: err.body || fallback };
    }
  }
  return { kind: "error", message: err instanceof Error ? err.message : fallback };
}
