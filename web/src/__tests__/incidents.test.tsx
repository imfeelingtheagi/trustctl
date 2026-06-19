import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
import { Incidents } from "@/pages/Incidents";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    graphBlastRadius: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, graphBlastRadius: apiMock.graphBlastRadius } };
});

function renderIncidents() {
  return render(
    <MemoryRouter>
      <Incidents />
    </MemoryRouter>,
  );
}

describe("incident response disclosure surface", () => {
  beforeEach(() => {
    apiMock.graphBlastRadius.mockReset().mockResolvedValue({
      node: { id: "cert:payments-api", kind: "credential", name: "payments-api certificate" },
      affected: [
        { id: "workload:payments", kind: "workload", name: "payments service" },
        { id: "resource:ledger", kind: "resource", name: "ledger database" },
      ],
      by_kind: { workload: 1, resource: 1 },
    });
  });

  it("loads blast-radius preview from the served graph endpoint and renders the compromise workflow", async () => {
    renderIncidents();

    expect(screen.getByRole("heading", { name: "Incidents" })).toBeInTheDocument();
    expect(screen.getByText("cert:payments-api")).toBeInTheDocument();
    expect(screen.getByText(/GET \/api\/v1\/graph\/blast-radius\/\{id\}/)).toBeInTheDocument();
    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("cert:payments-api"));
    expect(await screen.findByRole("heading", { name: "Blast-radius preview" })).toBeInTheDocument();
    expect(screen.getByText(/payments-api certificate/)).toBeInTheDocument();
    expect(screen.getByText("payments service")).toBeInTheDocument();
    expect(screen.getByText("ledger database")).toBeInTheDocument();
    expect(screen.getByText("Reissue-before-revoke plan")).toBeInTheDocument();
    expect(screen.getAllByText(/BACKEND-INCIDENT|BACKEND-CONNECTORS/).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: /execute|revoke|deploy|bypass|break glass/i })).not.toBeInTheDocument();
  });

  it("renders fleet reissue and break-glass fixtures with error state for unavailable graph preview", async () => {
    apiMock.graphBlastRadius.mockRejectedValueOnce(
      new ApiError(503, JSON.stringify({ detail: "graph projection is rebuilding" })),
    );
    renderIncidents();

    expect(await screen.findByRole("alert")).toHaveTextContent("graph projection is rebuilding");
    expect(screen.getByRole("heading", { name: "Fleet re-issuance for CA compromise" })).toBeInTheDocument();
    expect(screen.getByText("Wave 0")).toBeInTheDocument();
    expect(screen.getByText("48 percent complete")).toBeInTheDocument();
    expect(screen.getByText("2 failed targets")).toBeInTheDocument();
    expect(screen.getByText(/Audit receipts are held/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Break-glass procedures" })).toBeInTheDocument();
    expect(screen.getByText(/emergency declaration/i)).toBeInTheDocument();
    expect(screen.getByText(/quorum approval/i)).toBeInTheDocument();
    expect(screen.getAllByText(/offline issue/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/post-incident checklist/i).length).toBeGreaterThan(0);
  });
});
