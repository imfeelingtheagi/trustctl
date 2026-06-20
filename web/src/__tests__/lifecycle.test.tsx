import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Identities, graphNodeIdForIdentity } from "@/pages/Identities";
// The real ApiError class (the vi.mock below spreads the real module and only
// replaces `api`), used to simulate a 429 with a Retry-After hint (SURFACE-007).
import { ApiError } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    identities: vi.fn(),
    issuers: vi.fn(),
    owners: vi.fn(),
    getIdentity: vi.fn(),
    issueCertificate: vi.fn(),
    transitionIdentity: vi.fn(),
    approveIdentityAction: vi.fn(),
    graphBlastRadius: vi.fn(),
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
    // Fixtures use `status` — the field the SERVED Identity contract (OpenAPI) carries
    // and that identityState() reads (SURFACE-005: the FE no longer guesses `state`).
    apiMock.issueCertificate.mockReset().mockResolvedValue({ id: "new-1", name: "svc", status: "issued" });
    apiMock.getIdentity.mockReset();
    apiMock.transitionIdentity.mockReset().mockResolvedValue({ id: "x", name: "x", status: "x" });
    apiMock.approveIdentityAction.mockReset().mockResolvedValue({ resource: "req-1", action: "issue", approver: "ra", approvals: 1 });
    apiMock.graphBlastRadius.mockReset().mockResolvedValue({
      node: { id: "cert:demo", kind: "credential", name: "demo" },
      affected: [],
      by_kind: {},
    });
    apiMock.identities.mockReset();
  });

  it("maps served identity data to graph node IDs conservatively", () => {
    expect(
      graphNodeIdForIdentity({
        id: "dep-1",
        name: "tls-api",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "deployed",
      }),
    ).toBe("cert:dep-1");
    expect(
      graphNodeIdForIdentity({
        id: "dep-2",
        name: "tls-api",
        kind: "x509_certificate",
        owner_id: "owner-1",
        status: "deployed",
        attributes: { graph_node_id: "credential:dep-2" },
      }),
    ).toBe("credential:dep-2");
    expect(
      graphNodeIdForIdentity({
        id: "api-1",
        name: "api-key",
        kind: "api_key",
        owner_id: "owner-1",
        status: "deployed",
      }),
    ).toBeNull();
  });

  it("offers the state-appropriate action and calls the transition endpoint", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "req-1", name: "requested-svc", status: "requested" },
      { id: "iss-1", name: "issued-svc", status: "issued" },
      { id: "dep-1", name: "deployed-svc", status: "deployed" },
    ]);
    const user = userEvent.setup();
    renderIdentities();

    // A requested identity can be issued.
    const reqRow = (await screen.findByText("requested-svc")).closest("tr")!;
    await user.click(within(reqRow).getByRole("button", { name: /^issue$/i }));
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

  it("renders identities on the shared DataGrid with lifecycle badges and all six kind filters", async () => {
    const fixtures = [
      { id: "x509-1", name: "tls-api", kind: "x509_certificate", owner_id: "owner-x", status: "issued" },
      { id: "ssh-cert-1", name: "ssh-user", kind: "ssh_certificate", owner_id: "owner-sshc", status: "requested" },
      { id: "ssh-key-1", name: "deploy-key", kind: "ssh_key", owner_id: "owner-ssh", status: "deployed" },
      { id: "secret-1", name: "db-password", kind: "secret", owner_id: "owner-sec", status: "revoked" },
      { id: "api-key-1", name: "stripe-token", kind: "api_key", owner_id: "owner-api", status: "retired" },
      { id: "workload-1", name: "payments-worker", kind: "workload_identity", owner_id: "owner-work", status: "renewing" },
    ];
    apiMock.identities.mockResolvedValue(fixtures);
    const user = userEvent.setup();
    renderIdentities();

    const table = await screen.findByRole("table", { name: /credential identities/i });
    expect(table).toBeInTheDocument();
    expect(screen.getByText("issued")).toHaveAttribute("data-status-badge", "lifecycle");
    expect(screen.getByText("owner-x")).toBeInTheDocument();

    for (const identity of fixtures) {
      await user.selectOptions(screen.getByLabelText("Kind"), identity.kind);
      expect(await screen.findByText(identity.name)).toBeInTheDocument();
      for (const other of fixtures.filter((fixture) => fixture.id !== identity.id)) {
        expect(screen.queryByText(other.name)).not.toBeInTheDocument();
      }
    }

    await user.selectOptions(screen.getByLabelText("Kind"), "all");
    expect(await screen.findByText("tls-api")).toBeInTheDocument();
    expect(screen.getByText("payments-worker")).toBeInTheDocument();
  });

  it("loads kind-specific identity details and links owner plus issuer", async () => {
    const details = {
      "x509/1": {
        id: "x509/1",
        name: "tls-api",
        kind: "x509_certificate",
        owner_id: "owner-x",
        issuer_id: "issuer-x",
        status: "issued",
        not_after: "2026-07-01T00:00:00Z",
        attributes: { dns_names: ["api.example.test"] },
      },
      "ssh-key-1": {
        id: "ssh-key-1",
        name: "deploy-key",
        kind: "ssh_key",
        owner_id: "owner-ssh",
        status: "deployed",
        attributes: { fingerprint: "SHA256:abc" },
      },
      "workload-1": {
        id: "workload-1",
        name: "payments-worker",
        kind: "workload_identity",
        owner_id: "owner-workload",
        issuer_id: "issuer-workload",
        status: "requested",
        attributes: { spiffe_id: "spiffe://example.test/payments" },
      },
    };
    apiMock.identities.mockResolvedValue(Object.values(details));
    apiMock.getIdentity.mockImplementation(async (id: keyof typeof details) => details[id]);
    const user = userEvent.setup();
    renderIdentities();

    const x509Row = (await screen.findByText("tls-api")).closest("tr")!;
    await user.click(within(x509Row).getByRole("button", { name: /view details/i }));

    await waitFor(() => expect(apiMock.getIdentity).toHaveBeenCalledWith("x509/1"));
    expect(await screen.findByRole("dialog", { name: "Identity detail" })).toBeInTheDocument();
    expect(await screen.findByText("X.509 certificate identity")).toBeInTheDocument();
    expect(screen.getByText("Not after")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Owner owner-x" })).toHaveAttribute("href", "/owners?owner=owner-x");
    expect(screen.getByRole("link", { name: "Issuer issuer-x" })).toHaveAttribute(
      "href",
      "/coverage?feature=F5&issuer=issuer-x",
    );
    expect(screen.getByText(/api.example.test/)).toBeInTheDocument();

    const sshRow = screen.getByText("deploy-key").closest("tr")!;
    await user.click(within(sshRow).getByRole("button", { name: /view details/i }));
    expect(await screen.findByText("SSH key identity")).toBeInTheDocument();
    expect(screen.getByText("No issuer bound")).toBeInTheDocument();
    expect(screen.getByText(/SHA256:abc/)).toBeInTheDocument();

    const workloadRow = screen.getByText("payments-worker").closest("tr")!;
    await user.click(within(workloadRow).getByRole("button", { name: /view details/i }));
    expect(await screen.findByText("Workload identity")).toBeInTheDocument();
    expect(screen.getByText(/spiffe:\/\/example.test\/payments/)).toBeInTheDocument();
  });

  it("renders the per-credential activity timeline disclosure in the identity drawer (FE-022)", async () => {
    const identity = {
      id: "dep-1",
      name: "timeline-svc",
      kind: "x509_certificate",
      owner_id: "owner-1",
      status: "deployed",
    };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("timeline-svc")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /view details/i }));

    const dialog = await screen.findByRole("dialog", { name: "Identity detail" });
    expect(within(dialog).getByText("Credential activity timeline")).toBeInTheDocument();
    expect(within(dialog).getByText("Delivery status not exposed yet")).toBeInTheDocument();
    expect(within(dialog).getByText(/FE-PTR-OUTBOX/)).toBeInTheDocument();
    expect(within(dialog).getByText(/BACKEND-OUTBOX-STATUS/)).toBeInTheDocument();
    expect(within(dialog).getByText(/last_error/)).toBeInTheDocument();
    for (const state of ["Accepted", "Issuing", "Deploying", "Delivered / failed"]) {
      expect(within(dialog).getByText(state)).toBeInTheDocument();
    }
    expect(apiMock).not.toHaveProperty("outboxStatus");
  });

  it("disables invalid state-machine targets and sends the captured transition reason", async () => {
    const identity = { id: "req-1", name: "request-state-machine", kind: "x509_certificate", owner_id: "owner-1", status: "requested" };
    apiMock.identities.mockResolvedValue([identity]);
    apiMock.getIdentity.mockResolvedValue(identity);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("request-state-machine")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /view details/i }));

    expect(await screen.findByText("Lifecycle state machine")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Move to issued" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Move to deployed" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Move to retired" })).toBeDisabled();

    await user.type(screen.getByLabelText("Transition reason"), "approved in CAB-1234");
    await user.click(screen.getByRole("button", { name: "Move to issued" }));

    await waitFor(() =>
      expect(apiMock.transitionIdentity).toHaveBeenCalledWith("req-1", "issued", "approved in CAB-1234"),
    );
  });

  it("shows revoked and retired terminal handling in the state machine", async () => {
    const revoked = { id: "rev-1", name: "revoked-svc", kind: "api_key", owner_id: "owner-r", status: "revoked" };
    const retired = { id: "ret-1", name: "retired-svc", kind: "secret", owner_id: "owner-t", status: "retired" };
    apiMock.identities.mockResolvedValue([revoked, retired]);
    apiMock.getIdentity.mockImplementation(async (id: string) => (id === "rev-1" ? revoked : retired));
    const user = userEvent.setup();
    renderIdentities();

    const revokedRow = (await screen.findByText("revoked-svc")).closest("tr")!;
    await user.click(within(revokedRow).getByRole("button", { name: /view details/i }));
    expect(await screen.findByText(/Terminal trust state/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Move to issued" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Move to retired" })).toBeEnabled();

    const retiredRow = screen.getByText("retired-svc").closest("tr")!;
    await user.click(within(retiredRow).getByRole("button", { name: /view details/i }));
    expect(await screen.findByText(/Terminal state: retired identities/i)).toBeInTheDocument();
    for (const target of ["issued", "deployed", "renewing", "revoked", "retired"]) {
      expect(screen.getByRole("button", { name: `Move to ${target}` })).toBeDisabled();
    }
  });

  it("revokes an identity only after the user confirms (SURFACE-007)", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-9", name: "to-revoke", status: "deployed" }]);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("to-revoke")).closest("tr")!;
    // Clicking Revoke must NOT immediately call the destructive transition — it opens
    // a confirmation dialog that names the credential.
    await user.click(within(row).getByRole("button", { name: /^revoke$/i }));
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    const dialog = await screen.findByRole("alertdialog");
    // The dialog names the credential (it appears in both the heading and the body).
    expect(within(dialog).getAllByText(/to-revoke/).length).toBeGreaterThan(0);
    expect(within(dialog).getByRole("heading")).toHaveTextContent(/revoke.*to-revoke/i);
    expect(within(dialog).getByRole("button", { name: /yes, revoke/i })).toBeDisabled();

    // Confirming requires the credential name and sends the operator reason.
    await user.type(within(dialog).getByLabelText(/type credential name/i), "to-revoke");
    const reason = within(dialog).getByLabelText(/revocation reason/i);
    await user.clear(reason);
    await user.type(reason, "key compromise CAB-9001");
    await user.click(within(dialog).getByRole("button", { name: /yes, revoke/i }));
    await waitFor(() =>
      expect(apiMock.transitionIdentity).toHaveBeenCalledWith("dep-9", "revoked", "key compromise CAB-9001"),
    );
  });

  it("shows served blast-radius impact before destructive confirmation (FE-083)", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "dep-9", name: "to-revoke", kind: "x509_certificate", owner_id: "owner-1", status: "deployed" },
    ]);
    apiMock.graphBlastRadius.mockResolvedValue({
      node: { id: "cert:dep-9", kind: "credential", name: "to-revoke certificate" },
      affected: [
        { id: "workload:api", kind: "workload", name: "payments-api" },
        { id: "workload:worker", kind: "workload", name: "payments-worker" },
        { id: "resource:db", kind: "resource", name: "payments-db" },
      ],
      by_kind: { workload: 2, resource: 1 },
    });
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("to-revoke")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /^revoke$/i }));

    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("cert:dep-9"));
    const dialog = await screen.findByRole("alertdialog");
    expect(await within(dialog).findByText("Blast-radius impact")).toBeInTheDocument();
    expect(within(dialog).getByText(/cert:dep-9/)).toBeInTheDocument();
    expect(within(dialog).getByText(/3 downstream affected nodes/i)).toBeInTheDocument();
    expect(within(dialog).getByText("workload")).toBeInTheDocument();
    expect(within(dialog).getByText("2")).toBeInTheDocument();
    expect(within(dialog).getByText("resource")).toBeInTheDocument();
    expect(within(dialog).getByText("1")).toBeInTheDocument();
  });

  it("does not invent blast-radius impact when no graph node mapping is served (FE-083)", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "api-9", name: "api-key", kind: "api_key", owner_id: "owner-1", status: "deployed" },
    ]);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("api-key")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /^revoke$/i }));

    expect(apiMock.graphBlastRadius).not.toHaveBeenCalled();
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/no served graph node mapping/i)).toBeInTheDocument();
  });

  it("degrades blast-radius impact when the served graph request fails (FE-083)", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "dep-404", name: "missing-graph-node", kind: "x509_certificate", owner_id: "owner-1", status: "deployed" },
    ]);
    apiMock.graphBlastRadius.mockRejectedValue(new ApiError(404, JSON.stringify({ detail: "graph node not found" })));
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("missing-graph-node")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /^revoke$/i }));

    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("cert:dep-404"));
    const dialog = await screen.findByRole("alertdialog");
    expect(await within(dialog).findByText(/Blast-radius impact unavailable: graph node not found/i)).toBeInTheDocument();
  });

  it("cancelling the confirmation does not revoke (SURFACE-007)", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-9", name: "keep-me", status: "deployed" }]);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("keep-me")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /^revoke$/i }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: /cancel/i }));
    expect(apiMock.transitionIdentity).not.toHaveBeenCalled();
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("bulk revokes selected identities with count confirmation and per-item results", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "dep-1", name: "bulk-ok", kind: "x509_certificate", owner_id: "owner-1", status: "deployed" },
      { id: "dep-2", name: "bulk-fail", kind: "x509_certificate", owner_id: "owner-2", status: "deployed" },
      { id: "req-1", name: "not-selected", kind: "x509_certificate", owner_id: "owner-3", status: "requested" },
    ]);
    apiMock.transitionIdentity.mockImplementation(async (id: string) => {
      if (id === "dep-2") throw new ApiError(500, JSON.stringify({ detail: "connector queue unavailable" }));
      return { id, name: id, status: "revoked" };
    });
    const user = userEvent.setup();
    renderIdentities();

    await user.click(await screen.findByLabelText("Select bulk-ok"));
    await user.click(screen.getByLabelText("Select bulk-fail"));
    expect(screen.getByText("2 selected")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Bulk revoke selected" }));

    const dialog = await screen.findByRole("alertdialog", { name: /Revoke 2 selected identities/i });
    expect(within(dialog).getByText(/2 selected identities/i)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Confirm bulk revoke" }));

    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledTimes(2));
    expect(apiMock.transitionIdentity).toHaveBeenCalledWith("dep-1", "revoked", "bulk revoke via UI");
    expect(apiMock.transitionIdentity).toHaveBeenCalledWith("dep-2", "revoked", "bulk revoke via UI");
    expect(await screen.findByText("bulk-ok accepted")).toBeInTheDocument();
    expect(screen.getByText(/bulk-fail failed: connector queue unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/accepted 1; failed 1/i)).toBeInTheDocument();
  });

  it("shows served OCSP and CRL publication endpoints without fake health", async () => {
    apiMock.identities.mockResolvedValue([{ id: "dep-9", name: "revocation-docs", status: "deployed" }]);

    renderIdentities();

    expect(await screen.findByText("Revocation publication")).toBeInTheDocument();
    expect(screen.getByText("/ocsp/{tenant}")).toBeInTheDocument();
    expect(screen.getByText("/crl/{tenant}")).toBeInTheDocument();
    expect(screen.getByText(/BACKEND-PROTOCOL-STATUS/)).toBeInTheDocument();
    expect(screen.getByText(/live propagation health is not served yet/i)).toBeInTheDocument();
  });

  it("surfaces a 429 rate-limit with a Retry-After hint (SURFACE-007)", async () => {
    apiMock.identities.mockResolvedValue([{ id: "req-1", name: "svc", status: "requested" }]);
    apiMock.transitionIdentity.mockReset().mockRejectedValue(new ApiError(429, "rate limited", 12));
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("svc")).closest("tr")!;
    // Issue is non-destructive, so it runs without confirmation and hits the 429.
    await user.click(within(row).getByRole("button", { name: /^issue$/i }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/rate limited/i);
    expect(alert).toHaveTextContent(/12s/);
  });

  it("shows RA separation guardrails and served problem details for denied issue", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "req-1", name: "request-only-svc", kind: "x509_certificate", status: "requested" },
    ]);
    apiMock.transitionIdentity.mockReset().mockRejectedValue(
      new ApiError(
        403,
        JSON.stringify({
          detail: "certs:request principals cannot self-issue; a distinct approver is required",
        }),
      ),
    );
    const user = userEvent.setup();
    renderIdentities();

    expect(await screen.findByText(/A request-only principal cannot self-issue/i)).toBeInTheDocument();
    const row = screen.getByText("request-only-svc").closest("tr")!;
    const issue = within(row).getByRole("button", { name: /^issue$/i });
    await user.click(issue);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/certs:request principals cannot self-issue/i);
    expect(alert).toHaveTextContent(/distinct approver/i);
    expect(issue).toBeDisabled();
    expect(row).toHaveTextContent(/certs:request principals cannot self-issue/i);
  });

  it("moves dual-control approval decisions out of identity rows", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "req-1", name: "self-approval-svc", kind: "x509_certificate", status: "requested" },
    ]);
    renderIdentities();

    const row = (await screen.findByText("self-approval-svc")).closest("tr")!;
    expect(within(row).queryByRole("button", { name: /approve issue/i })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /review in approvals/i })).toHaveAttribute("href", "/approvals");
  });

  it("summarizes pending JIT approvals and links to the dedicated inbox", async () => {
    apiMock.identities.mockResolvedValue([
      {
        id: "jit-1",
        name: "jit-db",
        kind: "x509_certificate",
        status: "requested",
        attributes: {
          requester: "alice",
          approvals: "1/2",
          grant_expires_at: "2026-06-19T18:00:00Z",
        },
      },
    ]);
    renderIdentities();

    expect(await screen.findByText("JIT approvals moved to the inbox")).toBeInTheDocument();
    expect(screen.getAllByText("jit-db").length).toBeGreaterThan(0);
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByText("1/2")).toBeInTheDocument();
    expect(screen.getByText("2026-06-19T18:00:00Z")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /open approvals inbox/i })).toHaveAttribute("href", "/approvals");
    expect(screen.queryByRole("button", { name: /approve issue for jit-db/i })).not.toBeInTheDocument();
  });

  it("labels outbox delivery state as unavailable instead of claiming synchronous deploy", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "iss-1", name: "issued-svc", kind: "x509_certificate", status: "issued" },
    ]);
    renderIdentities();

    expect(await screen.findByText(/Outbox delivery status not served yet/i)).toBeInTheDocument();
    expect(document.querySelector('[data-state-primitive="unavailable"]')).toBeInTheDocument();
    const row = screen.getByText("issued-svc").closest("tr")!;
    expect(row).toHaveTextContent(/Deploy can be requested; outbox delivery receipt is not served/i);
  });

  it("discloses lifecycle automation as manual until schedules and outbox status are served", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "ren-1", name: "manual-renewal-svc", kind: "x509_certificate", status: "deployed" },
    ]);
    renderIdentities();

    expect(await screen.findByText("Lifecycle automation")).toBeInTheDocument();
    expect(screen.getByText(/renewal is manual today/i)).toBeInTheDocument();
    expect(screen.getByText("Automation layout preview")).toBeInTheDocument();
    expect(screen.getByText("Renew before")).toBeInTheDocument();
    expect(screen.getByText("Alert before")).toBeInTheDocument();
    expect(screen.getByText("Dry run")).toBeInTheDocument();
    expect(screen.getByText("Rollback")).toBeInTheDocument();
    expect(screen.getByText(/BACKEND-LIFECYCLE-AUTOMATION/)).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-OUTBOX-STATUS/).length).toBeGreaterThan(0);
    expect(screen.getByRole("link", { name: /use manual lifecycle transitions/i })).toHaveAttribute(
      "href",
      "#manual-lifecycle-transitions",
    );
    expect(screen.queryByRole("button", { name: /save schedule|run automation/i })).not.toBeInTheDocument();
  });

  it("reports idempotency protection after a successful lifecycle transition", async () => {
    apiMock.identities.mockResolvedValue([
      { id: "req-1", name: "idempotent-svc", kind: "x509_certificate", status: "requested" },
    ]);
    const user = userEvent.setup();
    renderIdentities();

    const row = (await screen.findByText("idempotent-svc")).closest("tr")!;
    await user.click(within(row).getByRole("button", { name: /^issue$/i }));

    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("req-1", "issued", expect.anything()));
    expect(await screen.findByRole("status")).toHaveTextContent(/Idempotency-Key protects/i);
    expect(screen.getByRole("status")).toHaveTextContent(/duplicate execution/i);
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

  it("does not record dual-control approval from the identity row", async () => {
    apiMock.identities.mockResolvedValue([{ id: "req-1", name: "needs-approval", status: "requested" }]);
    renderIdentities();

    const row = (await screen.findByText("needs-approval")).closest("tr")!;
    expect(within(row).queryByRole("button", { name: /approve issue/i })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /review in approvals/i })).toHaveAttribute("href", "/approvals");
    expect(apiMock.approveIdentityAction).not.toHaveBeenCalled();
  });
});
