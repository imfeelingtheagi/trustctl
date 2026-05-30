import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Identities } from "@/pages/Identities";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    identities: vi.fn(),
    issuers: vi.fn(),
    owners: vi.fn(),
    issueCertificate: vi.fn(),
    transitionIdentity: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderIdentities() {
  return render(
    <MemoryRouter>
      <Identities />
    </MemoryRouter>,
  );
}

describe("lifecycle actions from the UI", () => {
  beforeEach(() => {
    apiMock.issuers.mockReset().mockResolvedValue([{ id: "iss-1", kind: "x509_ca", name: "LE" }]);
    apiMock.owners.mockReset().mockResolvedValue([{ id: "own-1", kind: "workload", name: "team" }]);
    apiMock.issueCertificate.mockReset().mockResolvedValue({ id: "new-1", name: "svc", state: "issued" });
    apiMock.transitionIdentity.mockReset().mockResolvedValue({ id: "x", name: "x", state: "x" });
    apiMock.identities.mockReset();
  });

  it("offers the state-appropriate action and calls the transition endpoint", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "req-1", name: "requested-svc", state: "requested" },
      { id: "iss-1", name: "issued-svc", state: "issued" },
      { id: "dep-1", name: "deployed-svc", state: "deployed" },
    ]);
    const user = userEvent.setup();
    renderIdentities();

    // A requested identity can be issued.
    const reqRow = (await screen.findByText("requested-svc")).closest("tr")!;
    await user.click(within(reqRow).getByRole("button", { name: /issue/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("req-1", "issued", expect.anything()));

    // An issued identity can be deployed or revoked.
    const issRow = screen.getByText("issued-svc").closest("tr")!;
    await user.click(within(issRow).getByRole("button", { name: /deploy/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("iss-1", "deployed", expect.anything()));

    // A deployed identity can be renewed.
    const depRow = screen.getByText("deployed-svc").closest("tr")!;
    await user.click(within(depRow).getByRole("button", { name: /renew/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("dep-1", "renewing", expect.anything()));
  });

  it("revokes an identity from the UI", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-9", name: "to-revoke", state: "deployed" }]);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("to-revoke")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /revoke/i }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("dep-9", "revoked", expect.anything()));
  });

  it("creates (issues) a new identity from the page", async () => {
    apiMock.identities.mockResolvedValue([]);
    const user = userEvent.setup();
    renderIdentities();

    await user.click(await screen.findByRole("button", { name: /issue certificate|new identity/i }));
    await user.type(screen.getByLabelText(/name/i), "svc");
    await user.click(screen.getByRole("button", { name: /create|issue/i }));
    await waitFor(() => expect(apiMock.issueCertificate).toHaveBeenCalledWith(expect.objectContaining({ name: "svc" })));
  });
});
