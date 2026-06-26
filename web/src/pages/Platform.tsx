import { useEffect, useMemo, useState, type FormEvent } from "react";
import { KeyRound, Loader2, Plus, RefreshCw, ShieldCheck, UserMinus } from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { api, type APIToken, type Member, type OIDCMappingStatus, type RoleList } from "@/lib/api";

interface ScopeRequirement {
  feature: string;
  scope: string;
  route: string;
  denial: string;
}

interface APICapability {
  group: string;
  capability: string;
  operations: string;
  access: string;
}

const requiredScopes: ScopeRequirement[] = [
  {
    feature: "Access administration",
    scope: "access:write",
    route: "/platform",
    denial: "Member and API-token administration stays denied unless the principal has the access-admin write scope.",
  },
  {
    feature: "Certificate issuance",
    scope: "certs:issue",
    route: "/identities",
    denial: "Issuance remains denied until RA separation, dual control, and OPA allow the action.",
  },
  {
    feature: "Certificate inventory",
    scope: "certs:read",
    route: "/certificates",
    denial: "Inventory denial is shown as a generic permission message without tenant existence details.",
  },
  {
    feature: "Credential graph",
    scope: "graph:read",
    route: "/graph",
    denial: "Graph denials hide cross-tenant node details and show only the missing evidence scope.",
  },
  {
    feature: "Audit evidence",
    scope: "audit:read",
    route: "/audit",
    denial: "Audit denials suppress raw problem bodies that might mention another tenant.",
  },
  {
    feature: "Secrets",
    scope: "secrets:write",
    route: "/secrets",
    denial: "Secret workflows must never reveal or persist secret material when authorization fails.",
  },
];

const apiCapabilities: APICapability[] = [
  { group: "Access", capability: "Roles, OIDC mappings, members, offboarding, and API tokens", operations: "read, create, update, revoke", access: "session or API token; browser mutations use CSRF and idempotency" },
  { group: "Agents", capability: "Agent fleet and one-time enrollment tokens", operations: "read, mint", access: "session or API token; token minting uses browser session protection" },
  { group: "AI", capability: "Grounded query, RCA, and read-only MCP tool calls", operations: "query, analyze, inspect tools", access: "session or API token with tenant/RBAC filtering" },
  { group: "Audit", capability: "Event search and signed evidence export", operations: "read, export", access: "session or API token" },
  { group: "Certificates", capability: "Inventory, detail, and explicit public-certificate ingest", operations: "read, ingest", access: "session or API token; ingest is idempotent" },
  { group: "Graph", capability: "Credential graph, blast radius, reachability, and read-only graph query", operations: "read, analyze", access: "session or API token; graph query is read-only" },
  { group: "Identities", capability: "Identity request, approval, lifecycle transition, and detail read", operations: "read, request, approve, transition", access: "session or API token; mutations require idempotency" },
  { group: "Issuers", capability: "Issuer list, issuer detail, and CA authority workflows", operations: "read, create", access: "session or API token; CA mutations require browser session protection" },
  { group: "Owners", capability: "Owner directory and ownership updates", operations: "read, create, update, delete", access: "session-protected mutations" },
  { group: "Profiles", capability: "Issuance profile list, create, and version detail", operations: "read, create", access: "session or API token; profile creation is idempotent" },
  { group: "Risk", capability: "Risk-prioritized credential list", operations: "read, sort, filter", access: "session or API token" },
  { group: "Secrets", capability: "Native store, PKI secrets, shares, leases, rotation, sync, and machine login", operations: "read metadata, reveal once, create, rotate, delete, issue, redeem, renew, revoke", access: "session or API token; values are never stored in browser storage" },
];

const cliCommands = [
  {
    context: "Certificate inventory",
    command: "trstctl-cli certificates list --limit 50 --format json",
    parity: "same list contract as the certificate inventory",
  },
  {
    context: "Audit evidence",
    command: "trstctl-cli audit export --limit 500 --output audit-evidence.jws",
    parity: "same signed bundle as audit export",
  },
  {
    context: "Graph blast radius",
    command: "trstctl-cli graph blast-radius cert:payments-api --format json",
    parity: "same graph result as blast-radius analysis",
  },
  {
    context: "Agent enrollment",
    command: "trstctl-cli agents enroll-token --format json",
    parity: "same one-time token endpoint as the Agents page",
  },
  {
    context: "Access administration",
    command: "trstctl-cli access members list --include_offboarded true --format json",
    parity: "same member/offboarding contract as access administration",
  },
  {
    context: "Approver token mint",
    command: "trstctl-cli access tokens create -f approver-token.json --format json",
    parity: "same reveal-once token contract as approver-token minting",
  },
];

function browserTransport(): { label: string; detail: string; warning?: string } {
  if (typeof window === "undefined") {
    return { label: "Unknown", detail: "Browser transport is evaluated at runtime." };
  }
  if (window.location.protocol === "https:") {
    return {
      label: "HTTPS observed",
      detail: "The console is currently loaded over an encrypted browser connection.",
    };
  }
  return {
    label: "Local preview HTTP",
    detail: "The local Vite preview is HTTP. Production should be HTTPS or mTLS-terminated before operators use it.",
    warning: "Plaintext local preview. No private cert/key bytes are exposed in this browser view.",
  };
}

export function Platform() {
  const { user, preview } = useAuth();
  const transport = browserTransport();
  const csrfPresent = typeof document !== "undefined" && document.cookie.includes("trstctl_csrf=");
  const [roles, setRoles] = useState<RoleList | null>(null);
  const [oidc, setOIDC] = useState<OIDCMappingStatus | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [tokens, setTokens] = useState<APIToken[]>([]);
  const [accessLoading, setAccessLoading] = useState(true);
  const [accessBusy, setAccessBusy] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);
  const [accessNotice, setAccessNotice] = useState<string | null>(null);
  const [revealedToken, setRevealedToken] = useState<string | null>(null);
  const [memberSubject, setMemberSubject] = useState("");
  const [memberDisplayName, setMemberDisplayName] = useState("");
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRoles, setMemberRoles] = useState("operator");
  const [tokenSubject, setTokenSubject] = useState("");
  const [tokenScopes, setTokenScopes] = useState("certs:issue");
  const [offboardSubject, setOffboardSubject] = useState("");
  const [offboardReason, setOffboardReason] = useState("");
  const roleRows = useMemo(() => roles?.items ?? [], [roles]);

  async function loadAccessAdmin() {
    setAccessLoading(true);
    setAccessError(null);
    try {
      const [roleCatalog, oidcStatus, memberPage, tokenPage] = await Promise.all([
        api.accessRoles(),
        api.oidcMappingStatus(),
        api.members({ includeOffboarded: true, limit: 50 }),
        api.apiTokens({ includeRevoked: true, limit: 50 }),
      ]);
      setRoles(roleCatalog);
      setOIDC(oidcStatus);
      setMembers(memberPage.items ?? []);
      setTokens(tokenPage.items ?? []);
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessLoading(false);
    }
  }

  useEffect(() => {
    void loadAccessAdmin();
  }, []);

  async function onboardMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessBusy(true);
    setAccessError(null);
    setAccessNotice(null);
    try {
      await api.upsertMember(memberSubject.trim(), {
        display_name: memberDisplayName.trim(),
        email: memberEmail.trim(),
        roles: csvList(memberRoles),
        source: "manual",
      });
      setAccessNotice(`Onboarded ${memberSubject.trim()}`);
      setMemberSubject("");
      setMemberDisplayName("");
      setMemberEmail("");
      await loadAccessAdmin();
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessBusy(false);
    }
  }

  async function mintToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessBusy(true);
    setAccessError(null);
    setAccessNotice(null);
    setRevealedToken(null);
    try {
      const created = await api.createAPIToken({ subject: tokenSubject.trim(), scopes: csvList(tokenScopes) });
      setRevealedToken(created.token);
      setAccessNotice(`Minted API token for ${created.subject}`);
      setTokenSubject("");
      await loadAccessAdmin();
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessBusy(false);
    }
  }

  async function offboardMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessBusy(true);
    setAccessError(null);
    setAccessNotice(null);
    setRevealedToken(null);
    try {
      const result = await api.offboardMember(offboardSubject.trim(), { reason: offboardReason.trim() });
      setAccessNotice(`Offboarded ${result.member.subject}; revoked ${result.revoked_token_count} token(s)`);
      setOffboardSubject("");
      setOffboardReason("");
      await loadAccessAdmin();
    } catch (err) {
      setAccessError(err instanceof Error ? err.message : String(err));
    } finally {
      setAccessBusy(false);
    }
  }

  return (
    <section aria-labelledby="platform-heading" className="grid gap-6">
      <PageHeader
        titleId="platform-heading"
        title="Platform"
        description="Tenant context, access-control evidence, browser transport posture, auth status, and API capability view."
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <section className="ui-panel p-comfortable" aria-labelledby="tenant-heading">
          <h2 id="tenant-heading" className="text-title font-semibold">
            Tenant boundary
          </h2>
          <dl className="mt-3 grid gap-2 text-sm">
            <div>
              <dt className="font-medium text-muted-foreground">Subject</dt>
              <dd>{user?.email || user?.subject || "-"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Tenant ID from session</dt>
              <dd className="break-all font-mono text-xs">{user?.tenant_id || "-"}</dd>
            </div>
          </dl>
          <p className="mt-3 text-sm text-muted-foreground">
            The browser never chooses a tenant id through a route, query string, or form field. The backend session or API token supplies it, and PostgreSQL RLS
            enforces it below the API.
          </p>
        </section>

        <section className="ui-panel p-comfortable" aria-labelledby="transport-heading">
          <h2 id="transport-heading" className="text-title font-semibold">
            Transport
          </h2>
          <p className="mt-3 text-sm font-medium">{transport.label}</p>
          <p className="mt-1 text-sm text-muted-foreground">{transport.detail}</p>
          {transport.warning && <p className="mt-2 text-sm font-medium text-status-warning">{transport.warning}</p>}
        </section>

        <section className="ui-panel p-comfortable" aria-labelledby="auth-heading">
          <h2 id="auth-heading" className="text-title font-semibold">
            Auth session
          </h2>
          <dl className="mt-3 grid gap-2 text-sm">
            <div>
              <dt className="font-medium text-muted-foreground">Mode visible to UI</dt>
              <dd>{preview ? "local preview session" : "authenticated session"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">CSRF cookie</dt>
              <dd>{csrfPresent ? "present for browser mutations" : "not visible in this browser context"}</dd>
            </div>
          </dl>
          <p className="mt-3 text-sm text-muted-foreground">
            OIDC mapping status and API-token administration are shown in Access administration below. This card only reflects the browser session and CSRF
            posture.
          </p>
        </section>
      </div>

      <section aria-labelledby="access-heading">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <h2 id="access-heading" className="text-title font-semibold">
            Access administration
          </h2>
          <Button type="button" size="sm" variant="outline" onClick={() => void loadAccessAdmin()} disabled={accessLoading}>
            {accessLoading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
            Refresh
          </Button>
        </div>
        {accessError && (
          <p role="alert" className="mb-3 rounded-control border border-status-danger/30 bg-status-danger/10 px-3 py-2 text-sm text-status-danger">
            {accessError}
          </p>
        )}
        {accessNotice && (
          <p role="status" className="mb-3 rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
            {accessNotice}
          </p>
        )}
        {revealedToken && (
          <div className="mb-3 rounded-panel border border-status-warning/40 bg-status-warning/10 p-3 text-sm">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="font-medium">Reveal-once API token</p>
              <Button type="button" size="sm" variant="ghost" onClick={() => setRevealedToken(null)}>
                Dismiss
              </Button>
            </div>
            <code className="mt-2 block break-all rounded bg-background px-2 py-1 text-xs">{revealedToken}</code>
          </div>
        )}
        <div className="mb-4 grid gap-3 xl:grid-cols-3">
          <form onSubmit={(event) => void onboardMember(event)} className="ui-panel grid gap-3 p-comfortable">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-status-success" aria-hidden="true" />
              <h3 className="text-body font-semibold">Onboard member</h3>
            </div>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Subject</span>
              <input className="ui-input" value={memberSubject} onChange={(event) => setMemberSubject(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Display name</span>
              <input className="ui-input" value={memberDisplayName} onChange={(event) => setMemberDisplayName(event.target.value)} />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Email</span>
              <input className="ui-input" value={memberEmail} onChange={(event) => setMemberEmail(event.target.value)} />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Roles</span>
              <input className="ui-input" value={memberRoles} onChange={(event) => setMemberRoles(event.target.value)} required />
            </label>
            <Button type="submit" disabled={accessBusy || !memberSubject.trim()}>
              <Plus className="h-4 w-4" aria-hidden="true" />
              Save
            </Button>
          </form>
          <form onSubmit={(event) => void mintToken(event)} className="ui-panel grid gap-3 p-comfortable">
            <div className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-status-warning" aria-hidden="true" />
              <h3 className="text-body font-semibold">Mint API token</h3>
            </div>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Subject</span>
              <input className="ui-input" value={tokenSubject} onChange={(event) => setTokenSubject(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Scopes</span>
              <input className="ui-input" value={tokenScopes} onChange={(event) => setTokenScopes(event.target.value)} required />
            </label>
            <Button type="submit" disabled={accessBusy || !tokenSubject.trim()}>
              <KeyRound className="h-4 w-4" aria-hidden="true" />
              Mint
            </Button>
          </form>
          <form onSubmit={(event) => void offboardMember(event)} className="ui-panel grid gap-3 p-comfortable">
            <div className="flex items-center gap-2">
              <UserMinus className="h-4 w-4 text-status-danger" aria-hidden="true" />
              <h3 className="text-body font-semibold">Offboard member</h3>
            </div>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Subject</span>
              <input className="ui-input" value={offboardSubject} onChange={(event) => setOffboardSubject(event.target.value)} required />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium text-muted-foreground">Reason</span>
              <input className="ui-input" value={offboardReason} onChange={(event) => setOffboardReason(event.target.value)} />
            </label>
            <Button type="submit" variant="outline" className="text-status-danger" disabled={accessBusy || !offboardSubject.trim()}>
              <UserMinus className="h-4 w-4" aria-hidden="true" />
              Offboard
            </Button>
          </form>
        </div>
        <div className="mb-4 grid gap-4 xl:grid-cols-2">
          <div className="overflow-x-auto rounded-panel border border-border">
            <table className="ui-table min-w-[34rem]">
              <caption className="sr-only">Role catalog</caption>
              <thead>
                <tr>
                  <th scope="col">Role</th>
                  <th scope="col">Permissions</th>
                </tr>
              </thead>
              <tbody>
                {roleRows.map((role) => (
                  <tr key={role.name} className="align-top">
                    <td className="font-medium">{role.name}</td>
                    <td className="font-mono text-xs">{role.permissions.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="ui-panel p-comfortable text-sm">
            <h3 className="font-semibold">OIDC mapping status</h3>
            <dl className="mt-3 grid gap-2">
              <div>
                <dt className="font-medium text-muted-foreground">Enabled</dt>
                <dd>{oidc?.enabled ? "yes" : "no"}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Claims</dt>
                <dd>{[oidc?.tenant_claim || "no tenant claim", oidc?.groups_claim || "no groups claim"].join(" · ")}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Mappings</dt>
                <dd>{oidc?.tenant_mappings?.length ? oidc.tenant_mappings.map((m) => m.group || m.subject || m.claim).join(", ") : "none"}</dd>
              </div>
            </dl>
          </div>
        </div>
        <div className="mb-4 grid gap-4 xl:grid-cols-2">
          <div className="overflow-x-auto rounded-panel border border-border">
            <table className="ui-table min-w-[44rem]">
              <caption className="sr-only">Tenant members</caption>
              <thead>
                <tr>
                  <th scope="col">Subject</th>
                  <th scope="col">Roles</th>
                  <th scope="col">Status</th>
                  <th scope="col">Updated</th>
                </tr>
              </thead>
              <tbody>
                {members.map((member) => (
                  <tr key={member.subject} className="align-top">
                    <td className="font-medium">{member.subject}</td>
                    <td className="font-mono text-xs">{member.roles.join(", ")}</td>
                    <td>{member.status}</td>
                    <td>{formatDate(member.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="overflow-x-auto rounded-panel border border-border">
            <table className="ui-table min-w-[48rem]">
              <caption className="sr-only">API token metadata</caption>
              <thead>
                <tr>
                  <th scope="col">Subject</th>
                  <th scope="col">Scopes</th>
                  <th scope="col">Status</th>
                  <th scope="col">Created</th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((token) => (
                  <tr key={token.id} className="align-top">
                    <td className="font-medium">{token.subject}</td>
                    <td className="font-mono text-xs">{token.scopes.join(", ")}</td>
                    <td>{token.revoked_at ? "revoked" : "active"}</td>
                    <td>{formatDate(token.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <table className="ui-table">
          <caption className="sr-only">Required permission scopes by feature</caption>
          <thead>
            <tr>
              <th scope="col">Feature</th>
              <th scope="col">Required scope</th>
              <th scope="col">Route</th>
              <th scope="col">Denied-action copy</th>
            </tr>
          </thead>
          <tbody>
            {requiredScopes.map((item) => (
              <tr key={item.scope} className="align-top">
                <td>{item.feature}</td>
                <td className="font-mono text-xs">{item.scope}</td>
                <td>{item.route}</td>
                <td>{item.denial}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section aria-labelledby="api-spec-heading">
        <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="api-spec-heading" className="text-title font-semibold">
              API capability view
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">{apiCapabilities.length} capability groups from the product API contract.</p>
          </div>
          <span className="rounded-control border border-border bg-muted px-2 py-1 text-caption font-medium text-muted-foreground">Capability view</span>
        </div>
        <div className="overflow-x-auto rounded-panel border border-border">
          <table className="ui-table min-w-[60rem]">
            <caption className="sr-only">API capability groups</caption>
            <thead>
              <tr>
                <th scope="col">Group</th>
                <th scope="col">Capability</th>
                <th scope="col">Operations</th>
                <th scope="col">Access posture</th>
              </tr>
            </thead>
            <tbody>
              {apiCapabilities.map((capability) => (
                <tr key={capability.group} className="align-top">
                  <td>{capability.group}</td>
                  <td>{capability.capability}</td>
                  <td>{capability.operations}</td>
                  <td>{capability.access}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="cli-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="cli-heading" className="text-title font-semibold">
            CLI companion
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            These commands mirror the same customer workflows. The browser never renders bearer token values, and the examples avoid inline Authorization
            headers.
          </p>
        </div>
        <div className="overflow-x-auto rounded-panel border border-border">
          <table className="ui-table min-w-[66rem]">
            <caption className="sr-only">CLI companion commands</caption>
            <thead>
              <tr>
                <th scope="col">Context</th>
                <th scope="col">Token-safe command</th>
                <th scope="col">Parity note</th>
              </tr>
            </thead>
            <tbody>
              {cliCommands.map((row) => (
                <tr key={row.context} className="align-top">
                  <td className="font-medium">{row.context}</td>
                  <td className="font-mono text-xs">{row.command}</td>
                  <td>{row.parity}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

    </section>
  );
}

function csvList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatDate(value?: string): string {
  if (!value) return "-";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return value;
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(parsed);
}
