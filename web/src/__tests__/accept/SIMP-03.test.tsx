import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Audit } from "@/pages/Audit";
import { Policy } from "@/pages/Policy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    auditEvents: vi.fn(),
    complianceEvidencePack: vi.fn(),
    exportAudit: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderPolicy() {
  return render(
    <MemoryRouter>
      <Policy />
    </MemoryRouter>,
  );
}

function renderAudit(initialEntry = "/audit") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Audit />
    </MemoryRouter>,
  );
}

function evidencePack(framework: "soc2" | "cnsa-2.0") {
  return {
    format: "trstctl.compliance.evidence-pack.v1",
    framework,
    public_key_der: "BASE64PUBLICKEY",
    signed_export: {
      manifest: {
        framework,
        controls: [
          { id: `${framework}-crypto-inventory`, title: "Cryptographic inventory maintained", status: "evidenced", evidence: ["CBOM"] },
          { id: `${framework}-audit-trail`, title: "Tamper-evident audit trail", status: "evidenced", evidence: ["signed audit evidence log"] },
          { id: `${framework}-operator-attest`, title: "Operator attestation needed", status: "gap", evidence: ["operator attestation"] },
        ],
        posture: { total_crypto_assets: 4, quantum_vulnerable: framework === "cnsa-2.0" ? 1 : 0, post_quantum: framework === "cnsa-2.0" ? 3 : 1 },
        product_evidences: ["FIPS 203/204/205 migration posture from the CBOM"],
        operator_attests: ["organizational policies & governance"],
      },
      signature: "signed-by-export-key",
    },
  };
}

describe("SIMP-03 policy, audit, and compliance remediation", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.auditEvents.mockReset();
    apiMock.complianceEvidencePack.mockReset();
    apiMock.exportAudit.mockReset();
    apiMock.complianceEvidencePack.mockImplementation((framework: "soc2" | "cnsa-2.0") => Promise.resolve(evidencePack(framework)));
  });

  it("renders framework compliance evidence packs from the served client with a signed-bundle download", async () => {
    const user = userEvent.setup();
    renderPolicy();

    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenCalledWith("soc2"));
    expect(await screen.findByRole("heading", { name: "SOC 2 evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("trstctl.compliance.evidence-pack.v1")).toBeInTheDocument();
    expect(screen.getByText("3 controls")).toBeInTheDocument();
    expect(screen.getByText("2 evidenced")).toBeInTheDocument();
    expect(screen.getByText("1 gap")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
    expect(screen.getByText("FIPS 203/204/205 migration posture from the CBOM")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download signed bundle" })).toHaveAttribute("download", "soc2-evidence-pack.json");

    await user.click(screen.getByRole("button", { name: "CNSA 2.0" }));

    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenLastCalledWith("cnsa-2.0"));
    expect(await screen.findByRole("heading", { name: "CNSA 2.0 evidence pack" })).toBeInTheDocument();
    expect(screen.getByText("1 quantum vulnerable")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download signed bundle" })).toHaveAttribute("download", "cnsa-2.0-evidence-pack.json");
  });

  it("views policy decisions from Audit filters instead of a static Policy table", async () => {
    const user = userEvent.setup();
    apiMock.auditEvents
      .mockResolvedValueOnce([{ sequence: 1, id: "evt-1", type: "identity.issued", tenant_id: "tenant-1", time: "2026-06-26T12:00:00Z" }])
      .mockResolvedValueOnce([
        {
          sequence: 42,
          id: "evt-42",
          type: "policy.decision",
          tenant_id: "tenant-1",
          time: "2026-06-26T12:30:00Z",
          hash: "sha256:policy",
          actor: { email: "ra@example.test" },
          data: { decision: "deny", resource_id: "cert/payments", reason: "profile rejected SAN" },
        },
      ]);
    renderAudit();

    await screen.findByText("identity.issued");
    await user.click(screen.getByRole("button", { name: "Policy decisions" }));

    await waitFor(() => expect(apiMock.auditEvents).toHaveBeenLastCalledWith({ type: "policy.decision", limit: 50 }));
    expect(await screen.findByText("policy.decision")).toBeInTheDocument();
    expect(screen.getByDisplayValue("policy.decision")).toBeInTheDocument();
    expect(screen.getByText("cert/payments")).toBeInTheDocument();
    expect(screen.getByText("ra@example.test")).toBeInTheDocument();
  });

  it("removes notification-channel fixtures from Policy", async () => {
    renderPolicy();
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenCalled());

    expect(screen.queryByRole("heading", { name: "Notification integrations" })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/Slack|Microsoft Teams|PagerDuty|OpsGenie|secret:\/\/notify|channel fixture|test delivery/i);

    const source = readFileSync(path.join(process.cwd(), "src/pages/Policy.tsx"), "utf8");
    expect(source).not.toMatch(/notificationChannels|notificationFailures|secret:\/\/notify|Slack|Microsoft Teams|PagerDuty|OpsGenie|channel fixture|test delivery/i);
  });
});
