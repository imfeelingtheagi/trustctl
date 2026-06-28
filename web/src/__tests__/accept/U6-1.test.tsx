import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Policy } from "@/pages/Policy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    complianceEvidencePack: vi.fn(),
    decideNHIReviewItem: vi.fn(),
    exportAudit: vi.fn(),
    getNHIReviewCampaign: vi.fn(),
    nhiReviewCampaigns: vi.fn(),
    startNHIReviewCampaign: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  apiMock.complianceEvidencePack.mockReset().mockResolvedValue({
    framework: "soc2",
    format: "application/json",
    public_key_der: "BASE64DER",
    signed_export: { controls: 12, posture: "pass" },
  });
  apiMock.exportAudit.mockReset().mockResolvedValue({ format: "json", bundle: "BASE64BUNDLE" });
  apiMock.nhiReviewCampaigns.mockReset().mockResolvedValue({ items: [nhiReviewCampaign()] });
  apiMock.getNHIReviewCampaign.mockReset().mockResolvedValue(nhiReviewCampaign());
  apiMock.startNHIReviewCampaign.mockReset().mockResolvedValue(nhiReviewCampaign());
  apiMock.decideNHIReviewItem.mockReset().mockResolvedValue(nhiReviewCampaign("certified"));
});

function nhiReviewCampaign(status: "pending" | "certified" = "pending") {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    tenant_id: "tenant-1",
    name: "Quarterly NHI access certification",
    scope: "quarterly_access",
    reviewer_subject: "ra@example.test",
    requested_by: "ra@example.test",
    status: status === "pending" ? "open" : "completed",
    item_count: 1,
    pending_count: status === "pending" ? 1 : 0,
    certified_count: status === "certified" ? 1 : 0,
    revoked_count: 0,
    exception_count: 0,
    created_at: "2026-06-28T12:00:00Z",
    updated_at: "2026-06-28T12:00:00Z",
    items: [
      {
        item_id: "22222222-2222-4222-8222-222222222222",
        nhi_id: "svc-payments-api",
        nhi_kind: "workload",
        display_name: "Payments API workload",
        resource: "k8s://prod/payments",
        entitlement: "secret:payments/db/read",
        risk: "medium",
        evidence_refs: ["audit:nhi-discovery/latest"],
        status,
        created_at: "2026-06-28T12:00:00Z",
        updated_at: "2026-06-28T12:00:00Z",
      },
    ],
  };
}

describe("U6-1 compliance evidence-pack dashboard", () => {
  it("renders a framework's signed evidence pack and exports audit evidence from served endpoints", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <Policy />
      </MemoryRouter>,
    );
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenCalledWith("soc2"));
    expect(await screen.findByText("SOC 2 evidence pack")).toBeInTheDocument();
    expect(screen.getByText("Download signed bundle")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "PCI DSS" }));
    await waitFor(() => expect(apiMock.complianceEvidencePack).toHaveBeenCalledWith("pci-dss"));

    await user.click(screen.getByRole("button", { name: "Export audit evidence" }));
    await waitFor(() => expect(apiMock.exportAudit).toHaveBeenCalledWith({ limit: 500 }));
  });
});
