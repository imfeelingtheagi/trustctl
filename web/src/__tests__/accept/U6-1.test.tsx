import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Policy } from "@/pages/Policy";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    complianceEvidencePack: vi.fn(),
    exportAudit: vi.fn(),
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
});

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
