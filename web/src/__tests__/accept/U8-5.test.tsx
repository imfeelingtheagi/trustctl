import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Integrate } from "@/pages/Integrate";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    profiles: vi.fn(),
    discoverySources: vi.fn(),
    notificationRoutingPolicies: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

describe("U8-5 integrate hub", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.profiles.mockResolvedValue([]);
    apiMock.discoverySources.mockResolvedValue({ items: [] });
    apiMock.notificationRoutingPolicies.mockResolvedValue({ items: [] });
  });

  it("lists enrollment protocols, SDKs, and IaC artifacts with copyable references", async () => {
    render(
      <MemoryRouter>
        <Integrate />
      </MemoryRouter>,
    );
    expect(screen.getByRole("heading", { name: "Integrate" })).toBeInTheDocument();
    expect(screen.getByText("ACME")).toBeInTheDocument();
    expect(screen.getByText("EST")).toBeInTheDocument();
    expect(screen.getByText("SCEP")).toBeInTheDocument();
    expect(screen.getByText("Python SDK")).toBeInTheDocument();
    expect(screen.getByText("Terraform provider")).toBeInTheDocument();
    expect(screen.getByText("SPIRE upstream authority")).toBeInTheDocument();
    // copyable references
    expect(screen.getAllByRole("button", { name: /^Copy / }).length).toBeGreaterThan(5);
    await waitFor(() => expect(apiMock.profiles).toHaveBeenCalledTimes(1));
  });
});
