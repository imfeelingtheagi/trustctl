// Typed client over the certctl REST surface (S3.3 / S7.1 / S7.3). All requests
// carry the session cookie; a 401 surfaces as UnauthorizedError so the auth layer
// can redirect to login. Mutations send an Idempotency-Key (AN-5).

export class UnauthorizedError extends Error {
  constructor() {
    super("unauthorized");
    this.name = "UnauthorizedError";
  }
}

export class ApiError extends Error {
  status: number;
  body: string;
  constructor(status: number, body: string) {
    super(`request failed (${status})`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

export interface Me {
  subject: string;
  tenant_id: string;
  email?: string;
}

export interface Certificate {
  id: string;
  subject: string;
  issuer?: string;
  not_after?: string;
  status?: string;
}

export interface Owner {
  id: string;
  kind: string;
  name: string;
  email?: string;
}

export interface Issuer {
  id: string;
  kind: string;
  name: string;
}

export interface Identity {
  id: string;
  name: string;
  state?: string;
  status?: string;
  kind?: string;
  owner_id?: string;
  issuer_id?: string;
}

export interface Agent {
  id: string;
  name: string;
  status: string;
  version?: string;
  last_seen_at?: string;
}

export interface EnrollmentToken {
  token: string;
  enroll_path?: string;
}

export interface CredentialRisk {
  credential_id: string;
  subject: string;
  kind: string;
  score: number;
  exposure: number;
  owner_active: boolean;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: "include",
    headers: { Accept: "application/json", ...(init?.headers ?? {}) },
    ...init,
  });
  if (res.status === 401) throw new UnauthorizedError();
  if (!res.ok) throw new ApiError(res.status, await res.text());
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** newIdempotencyKey returns a fresh key so a retried mutation cannot execute
 * twice (AN-5). */
function newIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `idem-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

/** mutate issues a state-changing request with an optional JSON body and an
 * Idempotency-Key. */
function mutate<T>(method: string, path: string, body?: unknown): Promise<T> {
  return req<T>(path, {
    method,
    headers: { "Content-Type": "application/json", "Idempotency-Key": newIdempotencyKey() },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** Api is the client surface the UI depends on; it is mockable in tests. */
export interface Api {
  me(): Promise<Me>;
  certificates(): Promise<Certificate[]>;
  owners(): Promise<Owner[]>;
  createOwner(input: { kind: string; name: string; email?: string }): Promise<Owner>;
  issuers(): Promise<Issuer[]>;
  createIssuer(input: { kind: string; name: string }): Promise<Issuer>;
  identities(): Promise<Identity[]>;
  createIdentity(input: { kind: string; name: string; owner_id: string; issuer_id?: string }): Promise<Identity>;
  transitionIdentity(id: string, to: string, reason?: string): Promise<Identity>;
  /** issueCertificate is the one-call convenience the wizard and the "issue"
   * action use: it ensures an owner, creates the identity, and issues it. */
  issueCertificate(input: { name: string; ownerId?: string; issuerId?: string }): Promise<Identity>;
  agents(): Promise<Agent[]>;
  createEnrollmentToken(): Promise<EnrollmentToken>;
  risk(): Promise<CredentialRisk[]>;
}

export const api: Api = {
  me: () => req<Me>("/auth/me"),
  certificates: () =>
    req<{ items: Certificate[] }>("/api/v1/certificates").then((r) => r.items ?? []),
  owners: () => req<{ items: Owner[] }>("/api/v1/owners").then((r) => r.items ?? []),
  createOwner: (input) => mutate<Owner>("POST", "/api/v1/owners", input),
  issuers: () => req<{ items: Issuer[] }>("/api/v1/issuers").then((r) => r.items ?? []),
  createIssuer: (input) => mutate<Issuer>("POST", "/api/v1/issuers", input),
  identities: () => req<{ items: Identity[] }>("/api/v1/identities").then((r) => r.items ?? []),
  createIdentity: (input) => mutate<Identity>("POST", "/api/v1/identities", input),
  transitionIdentity: (id, to, reason) =>
    mutate<Identity>("POST", `/api/v1/identities/${id}/transitions`, { to, reason }),
  issueCertificate: async (input) => {
    let ownerId = input.ownerId;
    if (!ownerId) {
      const owner = await api.createOwner({ kind: "workload", name: input.name });
      ownerId = owner.id;
    }
    const identity = await api.createIdentity({
      kind: "x509_certificate",
      name: input.name,
      owner_id: ownerId,
      issuer_id: input.issuerId,
    });
    return api.transitionIdentity(identity.id, "issued", "first issuance via UI");
  },
  agents: () => req<{ agents: Agent[] }>("/api/v1/agents").then((r) => r.agents ?? []),
  createEnrollmentToken: () => mutate<EnrollmentToken>("POST", "/api/v1/agents/enrollment-tokens"),
  risk: () =>
    req<{ credentials: CredentialRisk[] }>("/api/v1/risk/credentials?sort=score").then(
      (r) => r.credentials ?? [],
    ),
};

/** loginURL is where the browser is sent to begin the OIDC flow. */
export const loginURL = "/auth/login";

/** identityState returns the lifecycle state regardless of which field carries
 * it. */
export function identityState(i: Identity): string {
  return i.state ?? i.status ?? "";
}
