import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
import { CAHierarchy } from "@/pages/CAHierarchy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    issuers: vi.fn(),
    createCACeremony: vi.fn(),
    approveCACeremony: vi.fn(),
    generateManagedKey: vi.fn(),
    rotateManagedKey: vi.fn(),
    revokeManagedKey: vi.fn(),
    zeroizeManagedKey: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderCAHierarchy() {
  return render(
    <MemoryRouter>
      <CAHierarchy />
    </MemoryRouter>,
  );
}

describe("CA hierarchy and custody surface", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.issuers.mockReset().mockResolvedValue([
      {
        id: "iss-root",
        name: "Root CA",
        kind: "x509_ca",
        internal: true,
        chain: ["Root CA"],
        public_key: "-----BEGIN PUBLIC KEY-----ROOT-----END PUBLIC KEY-----",
      },
      {
        id: "iss-ssh",
        name: "SSH CA",
        kind: "ssh_ca",
        internal: false,
        chain: ["Root CA", "SSH CA"],
        public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA",
      },
    ]);
    apiMock.createCACeremony.mockResolvedValue({
      id: "ceremony-root-1",
      tenant_id: "tenant-1",
      purpose: "create_root:Trust Root CA",
      threshold: 2,
      status: "pending",
      approvals: 1,
      opener: "ra@example.test",
      created_at: "2026-06-26T14:00:00Z",
    });
    apiMock.approveCACeremony.mockResolvedValue({
      id: "ceremony-root-1",
      tenant_id: "tenant-1",
      purpose: "create_root:Trust Root CA",
      threshold: 2,
      status: "approved",
      approvals: 2,
      opener: "ra@example.test",
      created_at: "2026-06-26T14:00:00Z",
    });
    apiMock.generateManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 1, state: "active", public_der: "BASE64PUBLICDER" });
    apiMock.rotateManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "active", public_der: "ROTATEDDER" });
    apiMock.revokeManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "revoked", public_der: "ROTATEDDER" });
    apiMock.zeroizeManagedKey.mockResolvedValue({ key_id: "kms/root-1", algorithm: "ECDSA-P256", version: 2, state: "zeroized" });
  });

  it("renders issuers with kind, chain, public key, and certificate links", async () => {
    renderCAHierarchy();

    expect(await screen.findByRole("heading", { name: "CA hierarchy" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Issuer visibility" })).toBeInTheDocument();
    expect((await screen.findAllByText("Root CA")).length).toBeGreaterThan(0);
    expect(screen.getByText("x509_ca")).toBeInTheDocument();
    expect(screen.getByText("ssh_ca")).toBeInTheDocument();
    expect(screen.getByText("Root CA -> SSH CA")).toBeInTheDocument();
    expect(screen.getByText(/BEGIN PUBLIC KEY/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Certificates for Root CA" })).toHaveAttribute("href", "/certificates?issuer=iss-root");
  });

  it("starts and approves a CA key ceremony through the API", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    await user.click(await screen.findByRole("button", { name: "Start root ceremony" }));

    await waitFor(() =>
      expect(apiMock.createCACeremony).toHaveBeenCalledWith({
        operation: "create_root",
        threshold: 2,
        spec: expect.objectContaining({ common_name: "Trust Root CA", signature_algorithm: "ECDSA-P256" }),
      }),
    );
    expect(await screen.findByText("ceremony-root-1")).toBeInTheDocument();
    expect(screen.getByText("1 / 2 approvals")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Approve ceremony ceremony-root-1" }));

    await waitFor(() => expect(apiMock.approveCACeremony).toHaveBeenCalledWith("ceremony-root-1"));
    expect(await screen.findByText("2 / 2 approvals")).toBeInTheDocument();
    expect(screen.getByText("approved")).toBeInTheDocument();
    expect(screen.queryByText("root:<sha256-of-ca-spec>")).not.toBeInTheDocument();
  });

  it("generates and acts on managed-key custody metadata without private key bytes", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    expect(await screen.findByRole("heading", { name: "Managed key custody" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Generate managed key" }));

    await waitFor(() => expect(apiMock.generateManagedKey).toHaveBeenCalledWith({ algorithm: "ECDSA-P256" }));
    expect(await screen.findByText("kms/root-1")).toBeInTheDocument();
    expect(screen.getByText("Version 1")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Rotate key kms/root-1" }));
    await waitFor(() => expect(apiMock.rotateManagedKey).toHaveBeenCalledWith("kms/root-1"));
    expect(await screen.findByText("Version 2")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Revoke key kms/root-1" }));
    await waitFor(() => expect(apiMock.revokeManagedKey).toHaveBeenCalledWith("kms/root-1"));
    expect(await screen.findByText("revoked")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Zeroize key kms/root-1" }));
    await waitFor(() => expect(apiMock.zeroizeManagedKey).toHaveBeenCalledWith("kms/root-1"));
    expect(await screen.findByText("zeroized")).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByText(/PRIVATE KEY-----/)).not.toBeInTheDocument();
  });

  it("surfaces issuer permission errors without hiding ceremony and custody actions", async () => {
    apiMock.issuers.mockRejectedValueOnce(new ApiError(403, JSON.stringify({ detail: "missing issuers:read" })));
    renderCAHierarchy();

    expect(await screen.findByText("Permission denied")).toBeInTheDocument();
    expect(screen.getByText("missing issuers:read")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start root ceremony" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generate managed key" })).toBeInTheDocument();
  });

  it("traps focus in the issuer configuration dialog and returns focus to the opener", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    const opener = await screen.findByRole("button", { name: "Configure ACME" });
    await user.click(opener);

    const dialog = await screen.findByRole("dialog", { name: "Configure ACME issuer" });
    const issuerName = within(dialog).getByLabelText("Issuer name");
    const close = within(dialog).getByRole("button", { name: "Close issuer form" });
    const cancel = within(dialog).getByRole("button", { name: "Cancel" });

    expect(issuerName).toHaveFocus();

    close.focus();
    await user.tab({ shift: true });
    expect(cancel).toHaveFocus();

    await user.tab();
    expect(close).toHaveFocus();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Configure ACME issuer" })).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });
});
