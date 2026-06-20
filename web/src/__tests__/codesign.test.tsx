import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { CodeSigning } from "@/pages/CodeSigning";

function renderCodeSigning() {
  return render(
    <MemoryRouter>
      <CodeSigning />
    </MemoryRouter>,
  );
}

describe("code signing disclosure surface", () => {
  it("renders signing requests with key modes, approvals, policy decisions, signature receipts, and audit", () => {
    renderCodeSigning();

    expect(screen.getByRole("heading", { name: "Code signing" })).toBeInTheDocument();
    expect(screen.getByText("key-backed signing")).toBeInTheDocument();
    expect(screen.getByText("keyless signing")).toBeInTheDocument();
    expect(screen.getByText("2 of 2 release approvers")).toBeInTheDocument();
    expect(screen.getAllByText(/artifact digest/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/policy allowed: release tag/)).toBeInTheDocument();
    expect(screen.getByText(/policy denied: missing build attestation/)).toBeInTheDocument();
    expect(screen.getByText(/signature download: pending backend artifact store/)).toBeInTheDocument();
    expect(screen.getAllByText(/audit/i).length).toBeGreaterThan(0);
    expect(screen.getByText("Code-signing workflow is library-only")).toBeInTheDocument();
    expect(screen.getByText(/cannot submit signing work/i)).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN .* PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /sign|approve|download signature|submit/i })).not.toBeInTheDocument();
  });
});
