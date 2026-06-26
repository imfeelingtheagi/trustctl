import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Workloads } from "@/pages/Workloads";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    issueDynamicLease: vi.fn(),
    renewDynamicLease: vi.fn(),
    revokeDynamicLease: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderWorkloads() {
  return render(
    <MemoryRouter>
      <Workloads />
    </MemoryRouter>,
  );
}

describe("WIRE-01 Workloads dynamic lease wiring", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.issueDynamicLease.mockResolvedValue({
      id: "lease-1",
      provider: "postgresql",
      role: "readonly-reporting",
      state: "active",
      issued_at: "2026-06-20T10:00:00Z",
      expires_at: "2026-06-20T10:20:00Z",
      credential: "SUPER-SECRET-LEASE-CREDENTIAL",
    });
    apiMock.renewDynamicLease.mockResolvedValue({
      id: "lease-1",
      provider: "postgresql",
      role: "readonly-reporting",
      state: "active",
      issued_at: "2026-06-20T10:00:00Z",
      expires_at: "2026-06-20T10:25:00Z",
    });
    apiMock.revokeDynamicLease.mockResolvedValue({
      id: "lease-1",
      provider: "postgresql",
      role: "readonly-reporting",
      state: "revoked",
      issued_at: "2026-06-20T10:00:00Z",
      expires_at: "2026-06-20T10:25:00Z",
    });
  });

  it("issues a real lease and revokes that returned lease through the API", async () => {
    const user = userEvent.setup();
    renderWorkloads();

    await user.clear(screen.getByLabelText("Provider"));
    await user.type(screen.getByLabelText("Provider"), "postgresql");
    await user.clear(screen.getByLabelText("Role"));
    await user.type(screen.getByLabelText("Role"), "readonly-reporting");
    await user.clear(screen.getByLabelText("TTL seconds"));
    await user.type(screen.getByLabelText("TTL seconds"), "1200");
    await user.click(screen.getByRole("button", { name: "Issue lease" }));

    expect(apiMock.issueDynamicLease).toHaveBeenCalledWith({ provider: "postgresql", role: "readonly-reporting", ttl_seconds: 1200 });

    const row = await screen.findByRole("row", { name: /lease-1 postgresql readonly-reporting active/i });
    expect(within(row).getByRole("button", { name: "Revoke lease lease-1" })).toBeInTheDocument();
    expect(screen.queryByText("SUPER-SECRET-LEASE-CREDENTIAL")).not.toBeInTheDocument();

    await user.click(within(row).getByRole("button", { name: "Revoke lease lease-1" }));
    expect(apiMock.revokeDynamicLease).toHaveBeenCalledWith("lease-1");
    expect(await screen.findByText("revoked")).toBeInTheDocument();
  });
});
