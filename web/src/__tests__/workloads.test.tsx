import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Workloads } from "@/pages/Workloads";

function renderWorkloads() {
  return render(
    <MemoryRouter>
      <Workloads />
    </MemoryRouter>,
  );
}

describe("workload identity disclosure surface", () => {
  it("renders ephemeral leases with expiry visualization and no live issue control", () => {
    renderWorkloads();

    expect(screen.getByRole("heading", { name: "Workload identity" })).toBeInTheDocument();
    expect(screen.getByText("Ephemeral credential leases")).toBeInTheDocument();
    expect(screen.getByText("00:00 issued")).toBeInTheDocument();
    expect(screen.getByText("00:45 renew window")).toBeInTheDocument();
    expect(screen.getByText("01:00 expires")).toBeInTheDocument();
    expect(screen.getByText("Browser lease controls are not served yet")).toBeInTheDocument();
    expect(screen.getByText("Ephemeral JIT issuance is REST and CLI only")).toBeInTheDocument();
    expect(screen.getByText(/POST \/api\/v1\/ephemeral/i)).toBeInTheDocument();
    expect(screen.getByText("X.509-SVID")).toBeInTheDocument();
    expect(screen.getByText("JWT-SVID")).toBeInTheDocument();
    expect(screen.getByText("PKI secret bundle")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /issue lease|revoke now|renew now/i })).not.toBeInTheDocument();
  });

  it("renders attestation fixtures without token leakage", () => {
    renderWorkloads();

    expect(screen.getByText("Workload attestation chain")).toBeInTheDocument();
    expect(screen.getByText("TPM quote")).toBeInTheDocument();
    expect(screen.getByText("AWS IID")).toBeInTheDocument();
    expect(screen.getByText("GCP instance identity")).toBeInTheDocument();
    expect(screen.getByText("Azure IMDS")).toBeInTheDocument();
    expect(screen.getByText("Kubernetes SAT")).toBeInTheDocument();
    expect(screen.getByText("GitHub OIDC")).toBeInTheDocument();
    expect(screen.getAllByText("accepted").length).toBeGreaterThan(0);
    expect(screen.getAllByText("rejected").length).toBeGreaterThan(0);
    expect(screen.getByText("expired")).toBeInTheDocument();
    expect(screen.getByText("wrong-tenant")).toBeInTheDocument();
    expect(screen.getByText("Raw attestation evidence stays out of the browser")).toBeInTheDocument();
    expect(screen.getByText(/Use the attested-issuance or ephemeral REST\/CLI paths for live proofs/i)).toBeInTheDocument();
    expect(screen.queryByText(/eyJ[a-z0-9_-]+/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
  });

  it("renders scoped AI-agent broker lifecycle as REST/CLI-only", () => {
    renderWorkloads();

    expect(screen.getByText("AI-agent / NHI broker")).toBeInTheDocument();
    expect(screen.getByText("spiffe://tenant/ai/build-agent")).toBeInTheDocument();
    expect(screen.getByText("mcp:read-only, secrets:read:ci, certs:issue:short")).toBeInTheDocument();
    expect(screen.getByText("credential lease audit event")).toBeInTheDocument();
    expect(screen.getByText(/POST \/api\/v1\/broker\/agent-identities/i)).toBeInTheDocument();
    expect(screen.getAllByText(/broker issuance is served through REST and CLI/i).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: /issue broker credential|approve agent|mint token/i })).not.toBeInTheDocument();
  });
});
