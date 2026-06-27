import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Operations } from "@/pages/Operations";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    rotationRuns: vi.fn(),
    connectorDeliveries: vi.fn(),
    identities: vi.fn(),
    approveIdentityAction: vi.fn(),
    transitionIdentity: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderOperations() {
  return render(
    <MemoryRouter>
      <Operations />
    </MemoryRouter>,
  );
}

describe("C10-2 operations queue", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.rotationRuns.mockResolvedValue({
      items: [
        {
          id: "rot-1",
          identity_id: "id-rot",
          status: "running",
          trigger: "expiry-window",
          predecessor_fingerprint: "sha256:old",
          successor_fingerprint: "sha256:new",
          created_at: "2026-06-26T10:00:00Z",
          updated_at: "2026-06-26T10:03:00Z",
          tenant_id: "t1",
        },
      ],
    });
    apiMock.connectorDeliveries.mockResolvedValue({
      items: [
        {
          id: "dep-1",
          connector: "kubernetes",
          destination: "cluster/prod",
          target: "ns/payments",
          status: "delivered",
          attempts: 2,
          fingerprint: "sha256:live",
          identity_id: "id-dep",
          created_at: "2026-06-26T10:01:00Z",
          updated_at: "2026-06-26T10:04:00Z",
          tenant_id: "t1",
        },
      ],
    });
    apiMock.identities.mockResolvedValue([
      {
        id: "jit-1",
        name: "jit-db",
        kind: "x509_certificate",
        status: "requested",
        owner_id: "owner-1",
        attributes: { requester: "dev@example.test", approvals: "1/2" },
      },
    ]);
    apiMock.approveIdentityAction.mockResolvedValue({ resource: "jit-1", action: "issue", approver: "ra@example.test", approvals: 2 });
    apiMock.transitionIdentity.mockResolvedValue({
      id: "jit-1",
      name: "jit-db",
      kind: "x509_certificate",
      status: "retired",
      owner_id: "owner-1",
    });
  });

  it("renders operations, filters them, records approval decisions, and fails closed for missing cancel support", async () => {
    const user = userEvent.setup();
    renderOperations();

    expect(await screen.findByRole("heading", { name: "Operations queue" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.rotationRuns).toHaveBeenCalledWith({ limit: 50 }));
    expect(apiMock.connectorDeliveries).toHaveBeenCalledWith({ limit: 50 });
    expect(apiMock.identities).toHaveBeenCalled();

    expect(screen.getByRole("combobox", { name: "Status filter" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Type filter" })).toBeInTheDocument();

    const rotationRow = screen.getByText("rot-1").closest("tr")!;
    expect(within(rotationRow).getByText("Rotation")).toBeInTheDocument();
    expect(within(rotationRow).getByText("running")).toBeInTheDocument();
    expect(within(rotationRow).getByText("1 / n/a")).toBeInTheDocument();

    const deploymentRow = screen.getByText("dep-1").closest("tr")!;
    expect(within(deploymentRow).getByText("Deployment")).toBeInTheDocument();
    expect(within(deploymentRow).getByText("2 / n/a")).toBeInTheDocument();
    expect(within(deploymentRow).getByText("Verified")).toBeInTheDocument();

    const approvalRow = screen.getByText("jit-db").closest("tr")!;
    expect(within(approvalRow).getByText("Awaiting approval")).toBeInTheDocument();
    await user.click(within(approvalRow).getByRole("button", { name: "Approve issue for jit-db" }));
    await waitFor(() => expect(apiMock.approveIdentityAction).toHaveBeenCalledWith("jit-1", "issue"));
    expect(await screen.findByRole("status")).toHaveTextContent("issue approval recorded for jit-1");

    await user.click(within(approvalRow).getByRole("button", { name: "Reject issue for jit-db" }));
    const dialog = await screen.findByRole("dialog", { name: "Reject issue for jit-db" });
    await user.type(within(dialog).getByLabelText("Reason"), "missing CAB approval");
    await user.click(within(dialog).getByRole("button", { name: "Reject request" }));
    await waitFor(() => expect(apiMock.transitionIdentity).toHaveBeenCalledWith("jit-1", "retired", "missing CAB approval"));

    await user.click(within(rotationRow).getByRole("button", { name: "Cancel rot-1" }));
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Cancel is not available for this operation yet. Use the owning workflow to stop or roll it back.",
    );
  });
});
