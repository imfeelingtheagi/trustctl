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
    importOfflineRootCA: vi.fn(),
    createOfflineIntermediateCSR: vi.fn(),
    importOfflineIntermediateCA: vi.fn(),
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
    apiMock.createCACeremony.mockImplementation(async (input: { operation: string }) => {
      const base = {
        tenant_id: "tenant-1",
        threshold: 2,
        status: "pending",
        approvals: 1,
        opener: "ra@example.test",
        created_at: "2026-06-26T14:00:00Z",
      };
      if (input.operation === "import_offline_root") {
        return { ...base, id: "ceremony-offline-root", purpose: "offline-root:root-cert-sha" };
      }
      if (input.operation === "create_offline_intermediate") {
        return { ...base, id: "ceremony-offline-intermediate", purpose: "offline-intermediate:ca-offline-root" };
      }
      return { ...base, id: "ceremony-root-1", purpose: "create_root:Trust Root CA" };
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
    apiMock.importOfflineRootCA.mockResolvedValue({
      id: "ca-offline-root",
      tenant_id: "tenant-1",
      kind: "root",
      common_name: "Offline Root CA",
      signer_handle: "",
      certificate_pem: "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----",
      serial: "01",
      max_path_len: 1,
      status: "active",
      created_at: "2026-06-26T14:00:00Z",
    });
    apiMock.createOfflineIntermediateCSR.mockResolvedValue({
      parent_id: "ca-offline-root",
      ceremony_id: "ceremony-offline-intermediate",
      signer_handle: "ca/offline-intermediate/ceremony-offline-intermediate",
      csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----",
    });
    apiMock.importOfflineIntermediateCA.mockResolvedValue({
      id: "ca-offline-intermediate",
      tenant_id: "tenant-1",
      parent_id: "ca-offline-root",
      kind: "intermediate",
      common_name: "Offline Issuing Intermediate",
      signer_handle: "ca/offline-intermediate/ceremony-offline-intermediate",
      certificate_pem: "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----",
      serial: "02",
      max_path_len: 0,
      status: "active",
      created_at: "2026-06-26T14:00:00Z",
    });
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

  it("drives the offline-root import and offline-signed intermediate workflow", async () => {
    const user = userEvent.setup();
    renderCAHierarchy();

    const rootPEM = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----";
    await user.type(await screen.findByLabelText("Offline root certificate PEM"), rootPEM);
    await user.click(screen.getByRole("button", { name: "Start offline-root ceremony" }));

    await waitFor(() =>
      expect(apiMock.createCACeremony).toHaveBeenCalledWith({
        operation: "import_offline_root",
        threshold: 2,
        certificate_pem: rootPEM,
        spec: expect.objectContaining({ common_name: "Offline Root CA", max_path_len: 1, signature_algorithm: "ECDSA-P256" }),
      }),
    );
    expect(await screen.findByDisplayValue("ceremony-offline-root")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Import offline root" }));
    await waitFor(() => expect(apiMock.importOfflineRootCA).toHaveBeenCalledWith(expect.objectContaining({ ceremony_id: "ceremony-offline-root", certificate_pem: rootPEM })));
    expect(await screen.findByText("ca-offline-root")).toBeInTheDocument();
    expect(screen.getByDisplayValue("ca-offline-root")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Start intermediate ceremony" }));
    await waitFor(() =>
      expect(apiMock.createCACeremony).toHaveBeenCalledWith({
        operation: "create_offline_intermediate",
        threshold: 2,
        parent_id: "ca-offline-root",
        spec: expect.objectContaining({ common_name: "Offline Issuing Intermediate", max_path_len: 0 }),
      }),
    );
    expect(await screen.findByDisplayValue("ceremony-offline-intermediate")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Generate signer CSR" }));
    await waitFor(() =>
      expect(apiMock.createOfflineIntermediateCSR).toHaveBeenCalledWith(
        "ca-offline-root",
        expect.objectContaining({ ceremony_id: "ceremony-offline-intermediate", spec: expect.objectContaining({ common_name: "Offline Issuing Intermediate" }) }),
      ),
    );
    const csrTextArea = (await screen.findByLabelText("Signer CSR PEM")) as HTMLTextAreaElement;
    expect(csrTextArea.value).toContain("BEGIN CERTIFICATE REQUEST");

    const intermediatePEM = "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----";
    await user.type(screen.getByLabelText("Offline-signed intermediate PEM"), intermediatePEM);
    await user.click(screen.getByRole("button", { name: "Import offline-signed intermediate" }));
    await waitFor(() =>
      expect(apiMock.importOfflineIntermediateCA).toHaveBeenCalledWith(
        "ca-offline-root",
        expect.objectContaining({ ceremony_id: "ceremony-offline-intermediate", certificate_pem: intermediatePEM }),
      ),
    );
    expect(await screen.findByText("ca-offline-intermediate")).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
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
