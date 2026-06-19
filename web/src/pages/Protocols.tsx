import { useState } from "react";
import { Copy } from "lucide-react";
import { UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";

interface ProtocolSnippet {
  label: string;
  command: string;
}

interface ProtocolSurface {
  id: string;
  name: string;
  feature: string;
  route: string;
  auth: string;
  env: string[];
  profile: string;
  snippets: ProtocolSnippet[];
  deferredRead: string;
  diagnostics: string;
}

const protocolSurfaces: ProtocolSurface[] = [
  {
    id: "acme",
    name: "ACME",
    feature: "F5",
    route: "GET /directory + POST /acme/...",
    auth: "ACME account key, challenge validation, profile gate",
    env: ["TRSTCTL_PROTOCOLS_ACME_ENABLED", "TRSTCTL_PROTOCOLS_ACME_TENANT_ID"],
    profile: "Use a profile that allows the acme protocol and serverAuth EKU.",
    snippets: [
      {
        label: "certbot",
        command:
          "certbot certonly --server https://trstctl.example.test/directory --manual --preferred-challenges dns -d api.example.test",
      },
      {
        label: "x/crypto/acme",
        command:
          'client := &acme.Client{DirectoryURL: "https://trstctl.example.test/directory"}',
      },
    ],
    deferredRead: "ACME accounts, orders, challenges, ARI state, and revocations",
    diagnostics: "No served ACME admin read lists orders or challenge outcomes yet.",
  },
  {
    id: "est",
    name: "EST",
    feature: "F22",
    route: "GET /.well-known/est/cacerts + POST /.well-known/est/simpleenroll",
    auth: "Bearer-token or TLS client auth, profile gate",
    env: ["TRSTCTL_PROTOCOLS_EST_ENABLED", "TRSTCTL_PROTOCOLS_EST_TENANT_ID"],
    profile: "Use a profile that allows the est protocol and the requested certificate shape.",
    snippets: [
      {
        label: "cacerts",
        command:
          "curl -s https://trstctl.example.test/.well-known/est/cacerts -o cacerts.p7",
      },
      {
        label: "simpleenroll",
        command:
          "curl -s -H 'Authorization: Bearer <bootstrap-token>' --data-binary @device.csr https://trstctl.example.test/.well-known/est/simpleenroll",
      },
    ],
    deferredRead: "EST enrollment transcript",
    diagnostics: "No served EST admin read exposes recent enrollments or protocol diagnostics yet.",
  },
  {
    id: "scep",
    name: "SCEP",
    feature: "F23",
    route: "GET/POST /scep",
    auth: "CMS transport, challenge-password gate, profile gate",
    env: ["TRSTCTL_PROTOCOLS_SCEP_ENABLED", "TRSTCTL_PROTOCOLS_SCEP_TENANT_ID", "TRSTCTL_PROTOCOLS_RA_KEY_FILE"],
    profile: "Use a profile that allows the scep protocol; keep the RA transport key on shared storage in HA.",
    snippets: [
      {
        label: "GetCACert",
        command:
          "sscep getca -u https://trstctl.example.test/scep -c trstctl-ca.pem",
      },
      {
        label: "PKIOperation",
        command:
          "sscep enroll -u https://trstctl.example.test/scep -c trstctl-ca.pem -k device.key -r device.csr -l device.pem",
      },
    ],
    deferredRead: "SCEP enrollment transcript",
    diagnostics: "No served SCEP admin read exposes recent PKIOperation outcomes or challenge failures yet.",
  },
  {
    id: "cmp",
    name: "CMP",
    feature: "F55",
    route: "POST /cmp",
    auth: "CMP protection key, profile gate",
    env: ["TRSTCTL_PROTOCOLS_CMP_ENABLED", "TRSTCTL_PROTOCOLS_CMP_TENANT_ID", "TRSTCTL_PROTOCOLS_RA_KEY_FILE"],
    profile: "Use a profile that allows the cmp protocol; keep the RA transport key on shared storage in HA.",
    snippets: [
      {
        label: "OpenSSL p10cr",
        command:
          "openssl cmp -server https://trstctl.example.test -path /cmp -cmd p10cr -csr device.csr -certout device.pem",
      },
    ],
    deferredRead: "CMP enrollment transcript",
    diagnostics: "No served CMP admin read exposes recent enrollment outcomes or response diagnostics yet.",
  },
];

export function Protocols() {
  const [copied, setCopied] = useState<string | null>(null);

  async function copySnippet(protocol: ProtocolSurface, snippet: ProtocolSnippet) {
    try {
      await navigator.clipboard?.writeText(snippet.command);
    } finally {
      setCopied(`${protocol.id}:${snippet.label}`);
    }
  }

  return (
    <section aria-labelledby="protocols-heading" className="grid gap-6">
      <div>
        <h1 id="protocols-heading" className="text-2xl font-semibold">
          Protocols
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Served-gated enrollment endpoints with exact paths, tenant-binding configuration, client setup commands, and honest gaps for live status reads.
        </p>
      </div>

      <section aria-labelledby="protocol-status-heading" className="border-y border-border py-4">
        <h2 id="protocol-status-heading" className="text-lg font-semibold">
          Protocol status source
        </h2>
        <div className="mt-3 grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <UnavailableState title="Live enabled-state is not served yet">
            `BACKEND-PROTOCOL-STATUS` must expose enabled/disabled state, tenant binding, public endpoint, and responder health before this console can claim a protocol is active. The protocol servers themselves are served-gated and default off.
          </UnavailableState>
          <div className="rounded-md border border-border p-3 text-sm">
            <p className="font-medium">Fail-closed startup and issuance posture</p>
            <p className="mt-1 text-muted-foreground">
              Each protocol requires an enabled flag plus a tenant ID. Startup rejects an enabled protocol with no tenant binding, and issuance refuses requests when no issuing CA/profile can satisfy the protocol request.
            </p>
          </div>
        </div>
      </section>

      <section aria-labelledby="protocol-table-heading">
        <h2 id="protocol-table-heading" className="mb-3 text-lg font-semibold">
          Endpoint register
        </h2>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[56rem] text-left text-sm">
            <caption className="sr-only">Served-gated enrollment protocol endpoints</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Protocol</th>
                <th scope="col" className="py-2 pr-4 font-medium">Public route</th>
                <th scope="col" className="py-2 pr-4 font-medium">Tenant binding</th>
                <th scope="col" className="py-2 pr-4 font-medium">Auth and profile gate</th>
                <th scope="col" className="py-2 pr-3 font-medium">Console status</th>
              </tr>
            </thead>
            <tbody>
              {protocolSurfaces.map((protocol) => (
                <tr key={protocol.id} className="border-b border-border align-top">
                  <td className="py-3 pl-3 pr-4">
                    <p className="font-medium">{protocol.name}</p>
                    <p className="text-xs text-muted-foreground">{protocol.feature}</p>
                  </td>
                  <td className="py-3 pr-4 font-mono text-xs">{protocol.route}</td>
                  <td className="py-3 pr-4">
                    <ul className="grid gap-1">
                      {protocol.env.map((env) => (
                        <li key={env} className="font-mono text-xs">{env}</li>
                      ))}
                    </ul>
                  </td>
                  <td className="py-3 pr-4">
                    <p>{protocol.auth}</p>
                    <p className="mt-1 text-muted-foreground">{protocol.profile}</p>
                  </td>
                  <td className="py-3 pr-3">
                    <span className="inline-flex rounded-md border border-amber-200 bg-amber-50 px-2 py-1 text-xs font-medium text-amber-800">
                      Status unknown to console
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="client-setup-heading" className="grid gap-4">
        <h2 id="client-setup-heading" className="text-lg font-semibold">
          Client setup
        </h2>
        {protocolSurfaces.map((protocol) => (
          <section key={protocol.id} aria-labelledby={`${protocol.id}-heading`} className="border-y border-border py-4">
            <div className="grid gap-4 lg:grid-cols-[14rem_minmax(0,1fr)_minmax(18rem,0.8fr)]">
              <div>
                <h3 id={`${protocol.id}-heading`} className="text-base font-semibold">
                  {protocol.name}
                </h3>
                <p className="mt-1 text-sm text-muted-foreground">{protocol.route}</p>
              </div>
              <div className="grid gap-3">
                {protocol.snippets.map((snippet) => {
                  const copiedKey = `${protocol.id}:${snippet.label}`;
                  return (
                    <div key={snippet.label} className="rounded-md border border-border p-3">
                      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                        <p className="text-sm font-medium">{snippet.label}</p>
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          aria-label={`Copy ${protocol.name} ${snippet.label} command`}
                          onClick={() => void copySnippet(protocol, snippet)}
                        >
                          <Copy className="h-4 w-4" aria-hidden="true" />
                          Copy
                        </Button>
                      </div>
                      <code className="block overflow-x-auto rounded bg-muted px-3 py-2 text-xs">{snippet.command}</code>
                      {copied === copiedKey && <p className="mt-2 text-xs text-muted-foreground">Copied command without token material.</p>}
                    </div>
                  );
                })}
              </div>
              <div className="grid content-start gap-3">
                <UnavailableState title={`${protocol.deferredRead} not served yet`}>
                  {protocol.diagnostics} This remains blocked until a served admin/status read exists; the page does not invent order, challenge, or transcript data.
                </UnavailableState>
                <p className="rounded-md border border-border p-3 text-sm text-muted-foreground">
                  Live tenant binding and endpoint health also need `BACKEND-PROTOCOL-STATUS`.
                </p>
              </div>
            </div>
          </section>
        ))}
      </section>
    </section>
  );
}
