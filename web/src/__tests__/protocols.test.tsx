import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Protocols } from "@/pages/Protocols";

function renderProtocols() {
  return render(
    <MemoryRouter>
      <Protocols />
    </MemoryRouter>,
  );
}

function installClipboardSpy() {
  const writeText = vi.fn().mockResolvedValue(undefined);
  const clipboard = { writeText };
  Object.defineProperty(window.navigator, "clipboard", {
    configurable: true,
    value: clipboard,
  });
  Object.defineProperty(globalThis.navigator, "clipboard", {
    configurable: true,
    value: clipboard,
  });
  return writeText;
}

describe("served-gated protocol surface", () => {
  it("renders ACME setup without claiming live enabled state", async () => {
    const writeText = installClipboardSpy();
    renderProtocols();

    expect(screen.getByRole("heading", { name: "Protocols" })).toBeInTheDocument();
    expect(screen.getAllByText("GET /directory + POST /acme/...").length).toBeGreaterThan(0);
    expect(screen.getByText("TRSTCTL_PROTOCOLS_ACME_ENABLED")).toBeInTheDocument();
    expect(screen.getByText("TRSTCTL_PROTOCOLS_ACME_TENANT_ID")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-PROTOCOL-STATUS/).length).toBeGreaterThan(0);
    expect(screen.getByText(/protocol servers themselves are served-gated and default off/i)).toBeInTheDocument();
    expect(screen.getByText(/issuance refuses requests when no issuing CA\/profile/i)).toBeInTheDocument();
    expect(screen.getAllByText("Status unknown to console").length).toBeGreaterThanOrEqual(4);
    expect(screen.queryByText(/^enabled$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^active$/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy ACME certbot command" }));

    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith(
        expect.stringContaining("--server https://trstctl.example.test/directory"),
      ),
    );
    expect(writeText).toHaveBeenCalledWith(expect.not.stringMatching(/Bearer|token|password/i));
    expect(screen.getByText("Copied command without token material.")).toBeInTheDocument();
  });

  it("renders EST, SCEP, and CMP endpoints with transcript reads honestly unavailable", () => {
    renderProtocols();

    expect(screen.getAllByText("GET /.well-known/est/cacerts + POST /.well-known/est/simpleenroll").length).toBeGreaterThan(0);
    expect(screen.getAllByText("GET/POST /scep").length).toBeGreaterThan(0);
    expect(screen.getAllByText("POST /cmp").length).toBeGreaterThan(0);
    expect(screen.getByText("TRSTCTL_PROTOCOLS_EST_TENANT_ID")).toBeInTheDocument();
    expect(screen.getByText("TRSTCTL_PROTOCOLS_SCEP_TENANT_ID")).toBeInTheDocument();
    expect(screen.getByText("TRSTCTL_PROTOCOLS_CMP_TENANT_ID")).toBeInTheDocument();
    expect(screen.getAllByText("TRSTCTL_PROTOCOLS_RA_KEY_FILE").length).toBe(2);
    expect(screen.getByText("EST enrollment transcript not served yet")).toBeInTheDocument();
    expect(screen.getByText("SCEP enrollment transcript not served yet")).toBeInTheDocument();
    expect(screen.getByText("CMP enrollment transcript not served yet")).toBeInTheDocument();
    expect(screen.getAllByText(/does not invent order, challenge, or transcript data/i).length).toBeGreaterThan(0);
  });

  it("renders SPIFFE, SSH CA, and TSA setup without exposing private key material", async () => {
    const writeText = installClipboardSpy();
    renderProtocols();

    expect(screen.getAllByText("gRPC UDS /tmp/trstctl-spiffe-workload.sock").length).toBeGreaterThan(0);
    expect(screen.getByText("TRSTCTL_PROTOCOLS_SPIFFE_TRUST_DOMAIN")).toBeInTheDocument();
    expect(screen.getByText("SPIFFE live workload status not served yet")).toBeInTheDocument();
    expect(screen.getByText(/X.509-SVID and JWT-SVID support/i)).toBeInTheDocument();

    expect(screen.getAllByText("GET /ssh/ca + POST /ssh/issue/user|host + GET /ssh/krl").length).toBeGreaterThan(0);
    expect(screen.getByText("TRSTCTL_PROTOCOLS_SSH_TENANT_ID")).toBeInTheDocument();
    expect(screen.getByText("SSH issue/revoke log not served yet")).toBeInTheDocument();
    expect(screen.getByText(/OpenSSH binary KRL/i)).toBeInTheDocument();

    expect(screen.getAllByText("POST /tsa").length).toBeGreaterThan(0);
    expect(screen.getByText("TRSTCTL_PROTOCOLS_TSA_CERT_FILE")).toBeInTheDocument();
    expect(screen.getByText("TSA issuance health not served yet")).toBeInTheDocument();
    expect(screen.getByText(/openssl ts -query/i)).toBeInTheDocument();
    expect(screen.getByText(/openssl ts -verify/i)).toBeInTheDocument();
    expect(screen.queryByText(/BEGIN PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByText(/BEGIN OPENSSH PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByText(/SVID private key:/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy TSA HTTP POST command" }));

    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith(expect.stringContaining("https://trstctl.example.test/tsa")),
    );
    expect(writeText).toHaveBeenCalledWith(expect.not.stringMatching(/PRIVATE KEY|password/i));
  });
});
