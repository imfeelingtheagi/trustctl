import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BreakGlassReconcile } from "@/components/breakglass";

const { apiMock } = vi.hoisted(() => ({ apiMock: { breakglassIssue: vi.fn(), breakglassReconcile: vi.fn() } }));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  apiMock.breakglassIssue.mockReset().mockResolvedValue({ reconciled: 1, audit_event_type: "breakglass.issued", bundle: { request_id: "bg-online-1" } });
  apiMock.breakglassReconcile.mockReset().mockResolvedValue({ reconciled: 2 });
});

const bundles = JSON.stringify([
  { request_id: "r1", subject: "CN=emergency", approvals: ["a", "b"], cert_der: "DER", signature: "SIG", issued_at: "2026-06-20T10:00:00Z", reason: "outage" },
]);

describe("U7-2 break-glass console", () => {
  it("issues an online break-glass bundle through the served endpoint", async () => {
    const user = userEvent.setup();
    render(<BreakGlassReconcile />);
    const body = JSON.stringify({
      request_id: "bg-online-1",
      subject: "svc.example",
      csr_der: "Y3Ny",
      reason: "regional outage",
      approvals: ["op1", "op2"],
      ttl_seconds: 900,
    });

    fireEvent.change(screen.getByLabelText("Online issue request (JSON)"), { target: { value: body } });
    await user.click(screen.getByRole("button", { name: "Issue break-glass certificate" }));

    await waitFor(() => expect(apiMock.breakglassIssue).toHaveBeenCalledWith(JSON.parse(body)));
    expect(await screen.findByText(/Issued and audited 1 break-glass bundle/i)).toBeInTheDocument();
  });

  it("reconciles offline-issued bundles through the served endpoint and reports the count", async () => {
    const user = userEvent.setup();
    render(<BreakGlassReconcile />);
    expect(screen.getByRole("heading", { name: "Break-glass reconciliation" })).toBeInTheDocument();

    // fireEvent.change avoids userEvent's special-character parsing of JSON braces/brackets.
    fireEvent.change(screen.getByLabelText("Offline-issued bundles (JSON)"), { target: { value: bundles } });
    await user.click(screen.getByRole("button", { name: "Reconcile break-glass bundles" }));

    await waitFor(() => expect(apiMock.breakglassReconcile).toHaveBeenCalled());
    expect(await screen.findByText(/Reconciled 2 break-glass bundles/i)).toBeInTheDocument();
  });
});
