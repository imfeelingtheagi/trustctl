import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Loader2 } from "lucide-react";
import { api, type Agent } from "@/lib/api";
import { PageHeader } from "@/components/PageHeader";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

type Step = 1 | 2 | 3 | 4;

const steps = [
  { n: 1, label: "Use internal CA" },
  { n: 2, label: "Install an agent" },
  { n: 3, label: "Issue your first cert" },
];

/** Wizard is the first-run flow (F12; UX target: first cert in <15 minutes): a
 * fresh install connects a CA, installs an agent, and issues its first
 * certificate in three guided steps. `pollMs` controls how often the agent step
 * checks for a freshly-registered agent (tunable for tests). */
export function Wizard({ pollMs = 4000 }: { pollMs?: number }) {
  const [step, setStep] = useState<Step>(1);
  const [agent, setAgent] = useState<Agent | null>(null);

  return (
    <section aria-labelledby="wizard-heading" className="mx-auto max-w-2xl">
      <PageHeader
        title="Set up trstctl"
        titleId="wizard-heading"
        description="Three steps to your first certificate."
      />

      <ol className="mb-8 flex gap-2" aria-label="Setup progress">
        {steps.map((s) => {
          const state = step > s.n ? "done" : step === s.n ? "current" : "upcoming";
          return (
            <li key={s.n} className="flex flex-1 items-center gap-2 text-body" aria-current={step === s.n ? "step" : undefined}>
              <span
                className={
                  state === "done"
                    ? "flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-brand-accent text-brand-accent-foreground shadow-elevation1"
                    : state === "current"
                      ? "flex h-6 w-6 shrink-0 items-center justify-center rounded-full border-2 border-brand-accent font-semibold text-brand-accent"
                      : "flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-border text-muted-foreground"
                }
              >
                {state === "done" ? <CheckCircle2 className="h-4 w-4" aria-hidden="true" /> : s.n}
              </span>
              <span className={state === "upcoming" ? "text-muted-foreground" : "font-medium"}>{s.label}</span>
            </li>
          );
        })}
      </ol>

      <Card>
        <CardContent className="pt-comfortable">
          {step === 1 && (
            <InternalCAStep onReady={() => setStep(2)} />
          )}
          {step === 2 && (
            <InstallAgentStep
              pollMs={pollMs}
              agent={agent}
              onAgent={setAgent}
              onContinue={() => setStep(3)}
            />
          )}
          {step === 3 && <IssueCertStep onIssued={() => setStep(4)} />}
          {step === 4 && <DoneStep />}
        </CardContent>
      </Card>
    </section>
  );
}

function InternalCAStep({ onReady }: { onReady: () => void }) {
  function submit(e: React.FormEvent) {
    e.preventDefault();
    onReady();
  }

  return (
    <form onSubmit={submit} aria-labelledby="step-ca-heading" className="space-y-4">
      <h2 id="step-ca-heading" className="text-title font-semibold">
        Use the internal Certificate Authority
      </h2>
      <p className="text-body text-muted-foreground">
        A fresh trstctl server provisions a signer-backed internal X.509 CA at boot.
        The first certificate uses that CA directly; external CA issuer routing is configured after setup.
      </p>
      <Button type="submit">
        Use internal CA
      </Button>
    </form>
  );
}

function InstallAgentStep({
  pollMs,
  agent,
  onAgent,
  onContinue,
}: {
  pollMs: number;
  agent: Agent | null;
  onAgent: (a: Agent) => void;
  onContinue: () => void;
}) {
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const minted = useRef(false);

  // Mint a one-time bootstrap token once, on entering the step.
  useEffect(() => {
    if (minted.current) return;
    minted.current = true;
    api
      .createEnrollmentToken()
      .then((t) => setToken(t.token))
      .catch((err) => setError(`Could not mint an enrollment token: ${String(err)}`));
  }, []);

  // Poll for the agent to register (UX target: first agent in <5 minutes).
  useEffect(() => {
    if (agent) return;
    const id = setInterval(() => {
      void check();
    }, pollMs);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agent, pollMs]);

  async function check() {
    setChecking(true);
    try {
      const list = await api.agents();
      if (list.length > 0) onAgent(list[0]);
    } catch {
      // transient; the next poll retries.
    } finally {
      setChecking(false);
    }
  }

  const origin = typeof window !== "undefined" ? window.location.origin : "https://trstctl.example";
  const command = [
    "trstctl-agent",
    `--enroll-url ${origin}`,
    "--bootstrap-token-file ./trstctl-bootstrap-token",
    "--server <control-plane-grpc:9443>",
    "--name <agent-name>",
    "--ca-bundle ./trstctl-ca.pem",
  ].join(" ");

  return (
    <section aria-labelledby="step-agent-heading" className="space-y-4">
      <h2 id="step-agent-heading" className="text-title font-semibold">
        Install an agent
      </h2>
      <p className="text-body text-muted-foreground">
        Save the one-time token to ./trstctl-bootstrap-token with 0600 permissions, then run this on
        a host inside your network. The agent generates its key locally — private keys never leave the
        host.
      </p>
      {token && (
        <div>
          <p className="text-caption font-medium text-muted-foreground">Bootstrap token</p>
          <code className="mt-1 block break-all rounded-control bg-muted px-3 py-2 text-caption">{token}</code>
        </div>
      )}
      <pre className="overflow-x-auto rounded-control border border-border bg-muted p-3 text-caption">
        <code>{command}</code>
      </pre>
      {error && (
        <p role="alert" className="text-body text-destructive">
          {error}
        </p>
      )}

      {agent ? (
        <p className="flex items-center gap-2 text-body font-medium text-status-success">
          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
          Agent {agent.name} registered.
        </p>
      ) : (
        <p className="flex items-center gap-2 text-body text-muted-foreground" role="status">
          {checking && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
          Waiting for the agent to register…
        </p>
      )}

      <div className="flex gap-2">
        <Button type="button" variant="outline" onClick={() => void check()}>
          Check for agent
        </Button>
        <Button type="button" onClick={onContinue} disabled={!agent}>
          Continue
        </Button>
      </div>
    </section>
  );
}

function IssueCertStep({ onIssued }: { onIssued: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.issueCertificate({ name: name.trim() || "first-service" });
      onIssued();
    } catch (err) {
      setError(`Could not issue the certificate: ${String(err instanceof Error ? err.message : err)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} aria-labelledby="step-cert-heading" className="space-y-4">
      <h2 id="step-cert-heading" className="text-title font-semibold">
        Issue your first cert
      </h2>
      <p className="text-body text-muted-foreground">
        Name the service this certificate belongs to. trstctl creates the owner and identity and
        issues it through the signer-backed internal CA.
      </p>
      <div className="space-y-1">
        <label htmlFor="svc-name" className="block text-body font-medium">
          Service name
        </label>
        <input
          id="svc-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="w-full rounded-control border border-border bg-background px-3 py-2 text-body"
          placeholder="e.g. payments-api"
        />
      </div>
      {error && (
        <p role="alert" className="text-body text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" disabled={busy}>
        {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
        Issue certificate
      </Button>
    </form>
  );
}

function DoneStep() {
  return (
    <section aria-labelledby="step-done-heading" className="space-y-4">
      <h2 id="step-done-heading" className="flex items-center gap-2 text-title font-semibold">
        <CheckCircle2 className="h-5 w-5 text-status-success" aria-hidden="true" />
        Your first certificate has been issued
      </h2>
      <p className="text-body text-muted-foreground">
        You're set up. trstctl will track this credential and alert before expiry. Renewal is a manual, one-click action today.
      </p>
      <div className="flex gap-2">
        <Link
          to="/certificates"
          className="inline-flex items-center justify-center gap-2 rounded-control bg-primary px-4 py-2 text-body font-medium text-primary-foreground shadow-elevation1 transition-[filter] hover:brightness-110 active:brightness-95 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          Track and renew certificates
        </Link>
      </div>
    </section>
  );
}
