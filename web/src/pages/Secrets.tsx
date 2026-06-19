import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Copy, Eye, KeyRound, Loader2, LogIn, RefreshCw, RotateCw, Share2, Trash2, X } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import {
  api,
  ApiError,
  type MachineLoginResponse,
  type PKISecret,
  type SecretMeta,
  type SecretValue,
  type ShareToken,
  type ShareValue,
} from "@/lib/api";

export function Secrets() {
  const [items, setItems] = useState<SecretMeta[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [createName, setCreateName] = useState("");
  const [createValue, setCreateValue] = useState("");
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const [revealed, setRevealed] = useState<SecretValue | null>(null);
  const [revealBusy, setRevealBusy] = useState<string | null>(null);
  const [revealError, setRevealError] = useState<string | null>(null);

  const [rotateName, setRotateName] = useState("");
  const [rotateValue, setRotateValue] = useState("");
  const [rotateBusy, setRotateBusy] = useState(false);
  const [rotateError, setRotateError] = useState<string | null>(null);

  const [deleteName, setDeleteName] = useState("");
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const [accessName, setAccessName] = useState("");
  const [accessResult, setAccessResult] = useState<{ name: string; version?: number } | null>(null);
  const [accessBusy, setAccessBusy] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);

  const [pkiName, setPkiName] = useState("");
  const [pkiTTL, setPkiTTL] = useState("900");
  const [pkiBusy, setPkiBusy] = useState(false);
  const [pkiError, setPkiError] = useState<string | null>(null);
  const [pkiBundle, setPkiBundle] = useState<PKISecret | null>(null);

  const [loginMethod, setLoginMethod] = useState("token");
  const [loginCredential, setLoginCredential] = useState("");
  const [loginBusy, setLoginBusy] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [session, setSession] = useState<MachineLoginResponse | null>(null);

  const [shareValueInput, setShareValueInput] = useState("");
  const [shareTTL, setShareTTL] = useState("300");
  const [shareBusy, setShareBusy] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [shareToken, setShareToken] = useState<ShareToken | null>(null);
  const [redeemToken, setRedeemToken] = useState("");
  const [redeemBusy, setRedeemBusy] = useState(false);
  const [redeemError, setRedeemError] = useState<string | null>(null);
  const [redeemed, setRedeemed] = useState<ShareValue | null>(null);

  async function load(cursor?: string) {
    setLoadError(null);
    setLoading(true);
    try {
      const page = await api.secretPage({ limit: 20, cursor });
      setItems((current) => (cursor ? mergeMeta(current, page.items) : page.items));
      setNextCursor(page.next_cursor);
      setAccessName((current) => current || page.items[0]?.name || "");
    } catch (err) {
      setLoadError(apiProblemMessage(err, "Secrets API unavailable or disabled"));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  const selectedMeta = useMemo(
    () => items.find((item) => item.name === accessName) ?? items[0] ?? null,
    [items, accessName],
  );

  async function submitCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setCreateError(null);
    setNotice(null);
    setCreateBusy(true);
    try {
      const meta = await api.createSecret({ name: createName, value: createValue });
      setItems((current) => mergeMeta(current, [meta]));
      setCreateName("");
      setCreateValue("");
      setNotice(`Secret ${meta.name} stored as version ${meta.version}. The value was sealed and is not shown after submit.`);
    } catch (err) {
      setCreateError(apiProblemMessage(err, "Could not create secret"));
    } finally {
      setCreateBusy(false);
    }
  }

  async function revealSecret(name: string) {
    setRevealError(null);
    setRevealed(null);
    setRevealBusy(name);
    try {
      setRevealed(await api.getSecret(name));
    } catch (err) {
      setRevealError(apiProblemMessage(err, "Could not reveal secret"));
    } finally {
      setRevealBusy(null);
    }
  }

  async function submitRotate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRotateError(null);
    setNotice(null);
    setRotateBusy(true);
    try {
      const meta = await api.rotateSecret(rotateName, { name: rotateName, value: rotateValue });
      setItems((current) => mergeMeta(current, [meta]));
      setRotateName("");
      setRotateValue("");
      setNotice(`Secret ${meta.name} rotated to version ${meta.version}. The replacement value was not rendered.`);
    } catch (err) {
      setRotateError(apiProblemMessage(err, "Could not rotate secret"));
    } finally {
      setRotateBusy(false);
    }
  }

  async function submitDelete(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setDeleteError(null);
    setNotice(null);
    setDeleteBusy(true);
    try {
      await api.deleteSecret(deleteName);
      setItems((current) => current.filter((item) => item.name !== deleteName));
      setNotice(`Secret ${deleteName} deleted by the served store endpoint.`);
      setDeleteName("");
      setDeleteConfirm("");
    } catch (err) {
      setDeleteError(apiProblemMessage(err, "Could not delete secret"));
    } finally {
      setDeleteBusy(false);
    }
  }

  async function runAccessTest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessError(null);
    setAccessResult(null);
    setAccessBusy(true);
    try {
      const value = await api.getSecret(accessName);
      setAccessResult({ name: value.name, version: value.version });
    } catch (err) {
      setAccessError(apiProblemMessage(err, "Access test failed"));
    } finally {
      setAccessBusy(false);
    }
  }

  async function submitPKI(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPkiError(null);
    setPkiBundle(null);
    setPkiBusy(true);
    try {
      const ttl = Number(pkiTTL);
      setPkiBundle(await api.issuePKISecret({ common_name: pkiName, ttl_seconds: Number.isFinite(ttl) ? ttl : undefined }));
      setPkiName("");
    } catch (err) {
      setPkiError(apiProblemMessage(err, "Could not issue PKI secret"));
    } finally {
      setPkiBusy(false);
    }
  }

  async function submitLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoginError(null);
    setSession(null);
    setLoginBusy(true);
    try {
      setSession(await api.machineLogin({ method: loginMethod, credential: loginCredential }));
      setLoginCredential("");
    } catch (err) {
      setLoginError(apiProblemMessage(err, "Machine login failed"));
    } finally {
      setLoginBusy(false);
    }
  }

  async function submitShare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setShareError(null);
    setShareToken(null);
    setShareBusy(true);
    try {
      const ttl = Number(shareTTL);
      setShareToken(await api.createShare({ value: shareValueInput, ttl_seconds: Number.isFinite(ttl) ? ttl : undefined }));
      setShareValueInput("");
    } catch (err) {
      setShareError(apiProblemMessage(err, "Could not create one-time share"));
    } finally {
      setShareBusy(false);
    }
  }

  async function submitRedeem(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRedeemError(null);
    setRedeemed(null);
    setRedeemBusy(true);
    try {
      setRedeemed(await api.redeemShare({ token: redeemToken }));
    } catch (err) {
      setRedeemError(apiProblemMessage(err, "Could not redeem one-time share"));
    } finally {
      setRedeemBusy(false);
    }
  }

  return (
    <section aria-labelledby="secrets-heading" className="grid gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 id="secrets-heading" className="text-2xl font-semibold">
            Secrets
          </h1>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Served secret-store, machine-login, PKI-secret, and one-time-share workflows. Metadata is durable; returned values, keys, and tokens are explicit reveal-once material.
          </p>
        </div>
        <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
          {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
          Refresh
        </Button>
      </div>

      {notice && <p role="status" className="rounded-md border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-800">{notice}</p>}

      {loadError && (
        <UnavailableState title="Secrets API unavailable or disabled">
          {loadError}. The served `/api/v1/secrets/*` surface is fail-closed until `secrets.enable_api` is enabled and a KEK is configured.
        </UnavailableState>
      )}

      <section aria-labelledby="store-heading" className="grid gap-4 border-y border-border py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="store-heading" className="text-lg font-semibold">
              Native secret store
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              `GET /api/v1/secrets/store` returns names and versions only. Create and rotate send a value to the backend, then this page drops the input and shows metadata.
            </p>
          </div>
        </div>

        <form aria-label="Create secret" onSubmit={(event) => void submitCreate(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Secret name</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={createName}
              onChange={(event) => setCreateName(event.target.value)}
              placeholder="app/db/password"
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Secret value</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              type="password"
              value={createValue}
              onChange={(event) => setCreateValue(event.target.value)}
              required
            />
          </label>
          <Button type="submit" className="self-end" disabled={createBusy || Boolean(loadError)}>
            {createBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            Create secret
          </Button>
        </form>
        {createError && <ErrorState title="Secret create failed">{createError}</ErrorState>}

        {loading && <LoadingState>Loading secret metadata...</LoadingState>}
        {!loading && !loadError && items.length === 0 && (
          <EmptyState title="No secrets stored yet">
            Create a tenant-scoped native-store secret. Only the name and version return to the metadata table.
          </EmptyState>
        )}
        {!loading && items.length > 0 && (
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full min-w-[58rem] text-left text-sm">
              <caption className="sr-only">Native secret metadata</caption>
              <thead>
                <tr className="border-b border-border text-muted-foreground">
                  <th scope="col" className="py-2 pl-3 pr-4 font-medium">Name</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Version</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Updated</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Created</th>
                  <th scope="col" className="py-2 pr-3 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.name} className="border-b border-border align-top">
                    <td className="py-2 pl-3 pr-4 font-medium">{item.name}</td>
                    <td className="py-2 pr-4 font-mono text-xs">v{item.version}</td>
                    <td className="py-2 pr-4">{formatDate(item.updated_at)}</td>
                    <td className="py-2 pr-4">{formatDate(item.created_at)}</td>
                    <td className="py-2 pr-3">
                      <div className="flex flex-wrap gap-2">
                        <Button type="button" size="sm" variant="outline" onClick={() => void revealSecret(item.name)} disabled={revealBusy === item.name}>
                          {revealBusy === item.name ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
                          Reveal once
                        </Button>
                        <Button type="button" size="sm" variant="outline" onClick={() => setRotateName(item.name)}>
                          <RotateCw className="h-4 w-4" aria-hidden="true" />
                          Prepare rotate
                        </Button>
                        <Button type="button" size="sm" variant="outline" onClick={() => setDeleteName(item.name)}>
                          <Trash2 className="h-4 w-4" aria-hidden="true" />
                          Prepare delete
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {nextCursor && (
          <Button type="button" variant="outline" onClick={() => void load(nextCursor)} disabled={loading}>
            Load next metadata page
          </Button>
        )}
        {revealError && <ErrorState title="Reveal failed">{revealError}</ErrorState>}
        {revealed && (
          <RevealPanel title={`Reveal-once value for ${revealed.name}`} onDismiss={() => setRevealed(null)} value={revealed.value}>
            Version {revealed.version ?? "latest"} returned by <code>GET /api/v1/secrets/store/{"{name}"}</code>. Dismiss clears it from the page.
          </RevealPanel>
        )}
      </section>

      <section aria-labelledby="rotate-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="rotate-heading" className="text-lg font-semibold">
            Manual rotation and delete
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Manual native-store rotation is served with <code>PUT /api/v1/secrets/store/{"{name}"}</code>. Scheduled rotation, rollback evidence, and downstream sync remain backend gaps.
          </p>
        </div>
        <UnavailableState title="Scheduled rotation and downstream sync not served yet">
          The broader rotation engine needs `BACKEND-LIFECYCLE-AUTOMATION`, `BACKEND-SECRETSYNC`, and `BACKEND-OUTBOX-STATUS`. This page exposes only the served per-secret rotate/delete controls.
        </UnavailableState>
        <form aria-label="Rotate secret" onSubmit={(event) => void submitRotate(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Secret to rotate</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={rotateName}
              onChange={(event) => setRotateName(event.target.value)}
              placeholder={selectedMeta?.name ?? "app/db/password"}
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Replacement value</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              type="password"
              value={rotateValue}
              onChange={(event) => setRotateValue(event.target.value)}
              required
            />
          </label>
          <Button type="submit" className="self-end" disabled={rotateBusy || Boolean(loadError)}>
            {rotateBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            Rotate secret
          </Button>
        </form>
        {rotateError && <ErrorState title="Rotation failed">{rotateError}</ErrorState>}

        <form aria-label="Delete secret" onSubmit={(event) => void submitDelete(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Secret to delete</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={deleteName}
              onChange={(event) => setDeleteName(event.target.value)}
              placeholder={selectedMeta?.name ?? "app/db/password"}
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Type the exact secret name</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={deleteConfirm}
              onChange={(event) => setDeleteConfirm(event.target.value)}
              required
            />
          </label>
          <Button type="submit" className="self-end" disabled={deleteBusy || !deleteName || deleteConfirm !== deleteName || Boolean(loadError)}>
            {deleteBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            Delete secret
          </Button>
        </form>
        {deleteError && <ErrorState title="Delete failed">{deleteError}</ErrorState>}
      </section>

      <section aria-labelledby="developer-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="developer-heading" className="text-lg font-semibold">
            Developer access
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            SDK and CLI examples target the served store contract and contain only names, tenants, and versions. The access test performs a read without rendering the value.
          </p>
        </div>
        <div className="grid gap-3 lg:grid-cols-2">
          <Snippet title="CLI injector" text={`trstctl secrets get ${selectedMeta?.name ?? "app/db/password"} --tenant current --format env --exec ./service`} />
          <Snippet title="TypeScript SDK" text={`const secret = await client.secrets.get("${selectedMeta?.name ?? "app/db/password"}");\nprocess.env.DB_PASSWORD = secret.value; // keep in process memory only`} />
        </div>
        <form aria-label="Secret access test" onSubmit={(event) => void runAccessTest(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Secret name</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={accessName}
              onChange={(event) => setAccessName(event.target.value)}
              placeholder="app/db/password"
              required
            />
          </label>
          <Button type="submit" className="self-end" variant="outline" disabled={accessBusy || Boolean(loadError)}>
            {accessBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
            Run access test
          </Button>
        </form>
        {accessError && <ErrorState title="Access test failed">{accessError}</ErrorState>}
        {accessResult && (
          <p role="status" className="rounded-md border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-800">
            Access test passed for {accessResult.name}; version {accessResult.version ?? "latest"} was reachable, and the value was not rendered.
          </p>
        )}
      </section>

      <section aria-labelledby="pki-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="pki-heading" className="text-lg font-semibold">
            PKI as a secret
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            `POST /api/v1/secrets/pki` returns a short-lived certificate bundle. The private key is shown only in the explicit result panel.
          </p>
        </div>
        <form aria-label="Issue PKI secret" onSubmit={(event) => void submitPKI(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_10rem_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Common name</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={pkiName}
              onChange={(event) => setPkiName(event.target.value)}
              placeholder="svc.internal"
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">TTL seconds</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              type="number"
              min="60"
              value={pkiTTL}
              onChange={(event) => setPkiTTL(event.target.value)}
            />
          </label>
          <Button type="submit" className="self-end" disabled={pkiBusy || Boolean(loadError)}>
            {pkiBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
            Issue PKI secret
          </Button>
        </form>
        {pkiError && <ErrorState title="PKI issue failed">{pkiError}</ErrorState>}
        {pkiBundle && (
          <RevealPanel title={`PKI bundle ${pkiBundle.serial}`} onDismiss={() => setPkiBundle(null)} value={`${pkiBundle.certificate}\n${pkiBundle.private_key}`}>
            Copy or download now. The serial, certificate, and private key came from the served PKI-secret endpoint and are cleared when dismissed.
          </RevealPanel>
        )}
      </section>

      <section aria-labelledby="machine-login-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="machine-login-heading" className="text-lg font-semibold">
            Machine login
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            `POST /api/v1/secrets/login` exchanges a machine credential for a scoped workload session. The submitted credential is cleared after submit and never echoed.
          </p>
        </div>
        <form aria-label="Machine login test" onSubmit={(event) => void submitLogin(event)} className="grid gap-3 md:grid-cols-[12rem_minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Method</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={loginMethod}
              onChange={(event) => setLoginMethod(event.target.value)}
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Credential</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              type="password"
              value={loginCredential}
              onChange={(event) => setLoginCredential(event.target.value)}
              required
            />
          </label>
          <Button type="submit" className="self-end" disabled={loginBusy || Boolean(loadError)}>
            {loginBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <LogIn className="h-4 w-4" aria-hidden="true" />}
            Test login
          </Button>
        </form>
        {loginError && <ErrorState title="Machine login failed">{loginError}</ErrorState>}
        {session && <MachineSession session={session} />}
        <UnavailableState title="Auth-method administration not served yet">
          Configured token methods, audience rules, issued-session ledger, and revoked methods need `BACKEND-TENANT-ADMIN`. This page exposes only the served login exchange.
        </UnavailableState>
      </section>

      <section aria-labelledby="share-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="share-heading" className="text-lg font-semibold">
            One-time sharing
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Create returns a bearer token once. Redeem returns the value once; a later redeem is expected to fail closed.
          </p>
        </div>
        <UnavailableState title="Secret-change approvals not served yet">
          Request/approve state for sensitive secret mutations needs `BACKEND-POLICY-AUTHOR`. This page exposes the served one-time share path and no fake approval queue.
        </UnavailableState>
        <div className="grid gap-4 xl:grid-cols-2">
          <form aria-label="Create one-time share" onSubmit={(event) => void submitShare(event)} className="grid content-start gap-3">
            <label className="grid gap-1 text-sm">
              <span className="font-medium">Value to share</span>
              <input
                className="rounded-md border border-input bg-background px-3 py-2"
                type="password"
                value={shareValueInput}
                onChange={(event) => setShareValueInput(event.target.value)}
                required
              />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium">TTL seconds</span>
              <input
                className="rounded-md border border-input bg-background px-3 py-2"
                type="number"
                min="60"
                value={shareTTL}
                onChange={(event) => setShareTTL(event.target.value)}
              />
            </label>
            <Button type="submit" disabled={shareBusy || Boolean(loadError)}>
              {shareBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Share2 className="h-4 w-4" aria-hidden="true" />}
              Create share
            </Button>
            {shareError && <ErrorState title="Share create failed">{shareError}</ErrorState>}
          </form>
          <form aria-label="Redeem one-time share" onSubmit={(event) => void submitRedeem(event)} className="grid content-start gap-3">
            <label className="grid gap-1 text-sm">
              <span className="font-medium">Share token</span>
              <input
                className="rounded-md border border-input bg-background px-3 py-2"
                value={redeemToken}
                onChange={(event) => setRedeemToken(event.target.value)}
                required
              />
            </label>
            <Button type="submit" variant="outline" disabled={redeemBusy || Boolean(loadError)}>
              {redeemBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
              Redeem share
            </Button>
            {redeemError && <ErrorState title="Share redeem failed">{redeemError}</ErrorState>}
          </form>
        </div>
        {shareToken && (
          <RevealPanel title="One-time share token" onDismiss={() => setShareToken(null)} value={shareToken.token}>
            Expires {formatDate(shareToken.expires_at)}. The token is bearer material; copy it now, then dismiss.
          </RevealPanel>
        )}
        {redeemed && (
          <RevealPanel title="Redeemed share value" onDismiss={() => setRedeemed(null)} value={redeemed.value}>
            This value is the exact-once redeem result. A second redeem should return the served failure.
          </RevealPanel>
        )}
      </section>
    </section>
  );
}

function RevealPanel({
  title,
  value,
  children,
  onDismiss,
}: {
  title: string;
  value: string;
  children: ReactNode;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = useState(false);
  async function copyValue() {
    try {
      await navigator.clipboard?.writeText(value);
      setCopied(true);
    } catch {
      setCopied(true);
    }
  }
  return (
    <div className="grid gap-3 rounded-md border border-border p-3 text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-medium">{title}</p>
          <p className="mt-1 text-muted-foreground">{children}</p>
        </div>
        <Button type="button" variant="ghost" size="sm" onClick={onDismiss}>
          <X className="h-4 w-4" aria-hidden="true" />
          Dismiss
        </Button>
      </div>
      <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded bg-muted px-3 py-2 font-mono text-xs">{value}</pre>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" size="sm" variant="outline" onClick={() => void copyValue()}>
          <Copy className="h-4 w-4" aria-hidden="true" />
          Copy once
        </Button>
        {copied && <span className="text-xs text-muted-foreground">Copied from this reveal panel.</span>}
      </div>
    </div>
  );
}

function Snippet({ title, text }: { title: string; text: string }) {
  return (
    <div className="grid gap-2 rounded-md border border-border p-3 text-sm">
      <p className="font-medium">{title}</p>
      <pre className="overflow-x-auto whitespace-pre-wrap rounded bg-muted px-3 py-2 font-mono text-xs">{text}</pre>
    </div>
  );
}

function MachineSession({ session }: { session: MachineLoginResponse }) {
  return (
    <dl className="grid gap-2 rounded-md border border-border p-3 text-sm md:grid-cols-2">
      <div>
        <dt className="font-medium text-muted-foreground">Session ID</dt>
        <dd className="break-all font-mono text-xs">{session.session_id}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Principal</dt>
        <dd>{session.principal}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Method</dt>
        <dd>{session.method}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Expires</dt>
        <dd>{formatDate(session.expires_at)}</dd>
      </div>
      <div className="md:col-span-2">
        <dt className="font-medium text-muted-foreground">Scopes</dt>
        <dd>{session.scopes.join(", ") || "No scopes served"}</dd>
      </div>
    </dl>
  );
}

function mergeMeta(current: SecretMeta[], incoming: SecretMeta[]): SecretMeta[] {
  const byName = new Map(current.map((item) => [item.name, item]));
  for (const item of incoming) byName.set(item.name, item);
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function formatDate(value?: string): string {
  if (!value) return "not served";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function apiProblemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.retryAfterSeconds != null) return `${fallback}: retry in ${err.retryAfterSeconds}s`;
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || err.message;
    } catch {
      return err.body || err.message;
    }
  }
  return err instanceof Error ? err.message : fallback;
}
