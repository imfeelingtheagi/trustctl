import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Wizard } from "@/pages/Wizard";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    createIssuer: vi.fn(),
    createEnrollmentToken: vi.fn(),
    agents: vi.fn(),
    issueCertificate: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderWizard() {
  return render(
    <MemoryRouter>
      <Wizard pollMs={50} />
    </MemoryRouter>,
  );
}

describe("first-run wizard", () => {
  beforeEach(() => {
    apiMock.createIssuer.mockReset();
    apiMock.createEnrollmentToken.mockReset().mockResolvedValue({ token: "BOOT-TOKEN-XYZ" });
    apiMock.agents.mockReset().mockResolvedValue([{ id: "ag-1", name: "edge-01", status: "online" }]);
    apiMock.issueCertificate.mockReset().mockResolvedValue({ id: "id-1", name: "payments", status: "issued" });
  });

  it("walks internal-CA → install-agent → issue-first-cert and issues a certificate", async () => {
    const user = userEvent.setup();
    renderWizard();

    // Step 1 — use the already-provisioned internal signer-backed CA. The wizard
    // must not post a name-only x509_ca issuer, because the served API rejects X.509
    // issuers without a certificate chain.
    expect(screen.getByRole("heading", { name: /use the internal certificate authority/i })).toBeInTheDocument();
    expect(screen.getByText(/signer-backed internal x\.509 ca/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /use internal ca/i }));
    expect(apiMock.createIssuer).not.toHaveBeenCalled();

    // Step 2 — install an agent: a one-time token is minted and shown in the
    // install command, then the wizard detects the agent's registration.
    await waitFor(() => expect(apiMock.createEnrollmentToken).toHaveBeenCalled());
    expect(await screen.findByText(/BOOT-TOKEN-XYZ/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /check (for agent|now)/i }));
    await waitFor(() => expect(screen.getByText(/edge-01/)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /continue|next/i }));

    // Step 3 — issue the first certificate.
    expect(await screen.findByRole("heading", { name: /issue your first cert/i })).toBeInTheDocument();
    await user.type(screen.getByLabelText(/name/i), "payments");
    await user.click(screen.getByRole("button", { name: /issue/i }));

    await waitFor(() => expect(apiMock.issueCertificate).toHaveBeenCalledWith({ name: "payments" }));
    expect(await screen.findByText(/first certificate (has been )?issued/i)).toBeInTheDocument();
  });

  it("does not promise automatic renewal after setup and links to the track/renew worklist", async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole("button", { name: /use internal ca/i }));
    await user.click(await screen.findByRole("button", { name: /check (for agent|now)/i }));
    await waitFor(() => expect(screen.getByText(/edge-01/)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /continue|next/i }));
    await user.type(await screen.findByLabelText(/name/i), "payments");
    await user.click(screen.getByRole("button", { name: /issue/i }));

    expect(await screen.findByText(/alert before expiry/i)).toBeInTheDocument();
    expect(screen.getByText(/manual, one-click action/i)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/rotate.*automatically|renew.*automatically/i);
    expect(screen.getByRole("link", { name: /track and renew certificates/i })).toHaveAttribute("href", "/certificates");
  });

  it("surfaces a failure to issue without creating an issuer", async () => {
    apiMock.issueCertificate.mockRejectedValueOnce(new Error("boom"));
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole("button", { name: /use internal ca/i }));
    await user.click(await screen.findByRole("button", { name: /check (for agent|now)/i }));
    await waitFor(() => expect(screen.getByText(/edge-01/)).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: /continue|next/i }));
    await user.type(await screen.findByLabelText(/name/i), "payments");
    await user.click(screen.getByRole("button", { name: /issue/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/boom|could not|failed/i);
    expect(apiMock.createIssuer).not.toHaveBeenCalled();
  });
});
