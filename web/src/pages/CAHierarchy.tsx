import { useEffect, useMemo, useState } from "react";
import { FileKey2, KeyRound, RefreshCw, ShieldCheck } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState, PermissionDeniedState, UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { api, ApiError, type Issuer } from "@/lib/api";

type Notice = { kind: "permission" | "error"; message: string };

const ceremonySteps = [
  {
    operation: "Create root",
    purpose: "root:<sha256-of-ca-spec>",
    guardrail: "m-of-n custodians approve exactly this root spec before the root exists",
  },
  {
    operation: "Create intermediate",
    purpose: "intermediate:<parent-ca-id>:<sha256-of-ca-spec>",
    guardrail: "quorum is bound to the parent CA and reviewed intermediate spec",
  },
  {
    operation: "Rotate CA",
    purpose: "rotation:<ca-id>",
    guardrail: "old authority is superseded only after the ceremony is consumed once",
  },
  {
    operation: "Cross-sign",
    purpose: "cross-sign:<ca-id>:<sha256-of-target-cert-der>",
    guardrail: "cross-signing is purpose-bound because it can create another valid trust path",
  },
];

const custodyRows = [
  {
    backend: "Local sealed key file",
    handle: "sealed://tenant-ca/root",
    purpose: "evaluation and single-node deployments",
    status: "root and intermediate CAs are bound to signer handles",
  },
  {
    backend: "PKCS#11 HSM",
    handle: "pkcs11://slot/ca-signing-key",
    purpose: "resident signing key, private material never leaves the device",
    status: "library-tier HSM/KMS lifecycle",
  },
  {
    backend: "YubiHSM 2 / cloud KMS",
    handle: "kms://tenant-ca/intermediate",
    purpose: "generate/import, sign, rotate, revoke, and zeroize through the custody boundary",
    status: "needs custody health and ceremony wiring",
  },
];

export function CAHierarchy() {
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState<Notice | null>(null);

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

  return (
    <section aria-labelledby="ca-heading" className="grid gap-6">
      <PageHeader
        titleId="ca-heading"
        title="CA hierarchy"
        description="Root and intermediate CA ceremonies use signer-backed custody. Rotation, cross-sign, and HSM/KMS lifecycle workflows are read-only here until their controls ship."
        actions={
          <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      <UnavailableState title="CA creation controls coming soon">
        Ceremony approvals, root/intermediate creation, and signer-backed leaf issuance are available outside this page. This page is read-only, so it renders no
        create-root, rotate-root, or ceremony execution controls.
      </UnavailableState>

      <section aria-labelledby="issuer-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <ShieldCheck className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="issuer-heading" className="text-title font-semibold">
              Issuer visibility
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              This view shows issuer name, kind, public key, internal flag, and chain metadata. Hierarchy mutations use the dedicated ceremony and authority
              workflows.
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
              m-of-n key ceremony model
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              A ceremony purpose is a tamper-evident label for exactly one CA-key operation. The workflow consumes root/intermediate quorums once, emits
              tenant-scoped events, and rejects purpose mismatch or replay.
            </p>
          </div>
        </div>
        <a className="text-sm font-medium text-brand-accent underline" href="/docs/runbooks/key-ceremony.md">
          Key ceremony runbook
        </a>
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[48rem]">
            <caption className="sr-only">CA ceremony purpose model</caption>
            <thead>
              <tr>
                <th scope="col">Operation</th>
                <th scope="col">Purpose string</th>
                <th scope="col">Guardrail</th>
              </tr>
            </thead>
            <tbody>
              {ceremonySteps.map((step) => (
                <tr key={step.operation} className="align-top">
                  <td className="font-medium">{step.operation}</td>
                  <td className="font-mono text-xs">{step.purpose}</td>
                  <td>{step.guardrail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <UnavailableState title="Rotation and cross-sign controls coming soon">
          Root and intermediate creation are available through authenticated workflows. Rotation and cross-signing still need operator controls before this page
          can run them.
        </UnavailableState>
      </section>

      <section aria-labelledby="custody-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <KeyRound className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="custody-heading" className="text-title font-semibold">
              Key custody and HSM/KMS
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              Private key bytes never belong in the browser. Custody surfaces should expose handles, backend type, purpose constraints, and health only.
            </p>
          </div>
        </div>
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[48rem]">
            <caption className="sr-only">Key custody metadata preview</caption>
            <thead>
              <tr>
                <th scope="col">Backend</th>
                <th scope="col">Public handle</th>
                <th scope="col">Purpose</th>
                <th scope="col">Serving status</th>
              </tr>
            </thead>
            <tbody>
              {custodyRows.map((row) => (
                <tr key={row.backend} className="align-top">
                  <td className="font-medium">{row.backend}</td>
                  <td className="font-mono text-xs">{row.handle}</td>
                  <td>{row.purpose}</td>
                  <td>{row.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <UnavailableState title="HSM/KMS lifecycle controls coming soon">
          HSM slot health, generate/import, resident-key rotation, revoke, and zeroize stay behind the custody boundary. This page does not yet expose lifecycle
          controls for that workflow.
        </UnavailableState>
      </section>
    </section>
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
