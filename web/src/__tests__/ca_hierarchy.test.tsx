import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
import { CAHierarchy } from "@/pages/CAHierarchy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    issuers: vi.fn(),
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
  });

  it("renders served issuers with kind, chain, public key, and certificate links", async () => {
    renderCAHierarchy();

    expect(await screen.findByRole("heading", { name: "CA hierarchy" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Served issuer visibility" })).toBeInTheDocument();
    expect(screen.getAllByText("Root CA").length).toBeGreaterThan(0);
    expect(screen.getByText("x509_ca")).toBeInTheDocument();
    expect(screen.getByText("ssh_ca")).toBeInTheDocument();
    expect(screen.getByText("Root CA -> SSH CA")).toBeInTheDocument();
    expect(screen.getByText(/BEGIN PUBLIC KEY/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Certificates for Root CA" })).toHaveAttribute(
      "href",
      "/certificates?issuer=iss-root",
    );
  });

  it("explains m-of-n hierarchy ceremonies without create or rotate controls", async () => {
    renderCAHierarchy();

    expect(await screen.findByText("CA hierarchy ceremony API not served yet")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-CA-HIERARCHY/).length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: "Key ceremony runbook" })).toHaveAttribute(
      "href",
      "/docs/runbooks/key-ceremony.md",
    );
    expect(screen.getByText("root:<sha256-of-ca-spec>")).toBeInTheDocument();
    expect(screen.getByText("intermediate:<parent-ca-id>:<sha256-of-ca-spec>")).toBeInTheDocument();
    expect(screen.getByText("cross-sign:<ca-id>:<sha256-of-target-cert-der>")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /create root|rotate root|start ceremony|cross-sign/i })).not.toBeInTheDocument();
  });

  it("shows HSM/KMS custody metadata without key bytes or key lifecycle mutation controls", async () => {
    renderCAHierarchy();

    expect(await screen.findByRole("heading", { name: "Key custody and HSM/KMS" })).toBeInTheDocument();
    expect(screen.getByText("PKCS#11 HSM")).toBeInTheDocument();
    expect(screen.getByText("pkcs11://slot/ca-signing-key")).toBeInTheDocument();
    expect(screen.getByText("YubiHSM 2 / cloud KMS")).toBeInTheDocument();
    expect(screen.getByText("HSM/KMS lifecycle API not served yet")).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByText(/PRIVATE KEY-----/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /generate key|import key|zeroize|rotate hsm/i })).not.toBeInTheDocument();
  });

  it("surfaces issuer permission errors without hiding the ceremony disclosure", async () => {
    apiMock.issuers.mockRejectedValueOnce(
      new ApiError(403, JSON.stringify({ detail: "missing issuers:read" })),
    );
    renderCAHierarchy();

    expect(await screen.findByText("Permission denied")).toBeInTheDocument();
    expect(screen.getByText("missing issuers:read")).toBeInTheDocument();
    expect(screen.getByText("Hierarchy mutations are library-tier")).toBeInTheDocument();
  });
});
