import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BreakGlassReconcile } from "@/components/breakglass";

const { apiMock } = vi.hoisted(() => ({ apiMock: { breakglassReconcile: vi.fn() } }));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

beforeEach(() => {
  apiMock.breakglassReconcile.mockReset().mockResolvedValue({ reconciled: 2 });
});

const bundles = JSON.stringify([
  { request_id: "r1", subject: "CN=emergency", approvals: ["a", "b"], cert_der: "DER", signature: "SIG", issued_at: "2026-06-20T10:00:00Z", reason: "outage" },
]);

describe("U7-2 break-glass console", () => {
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
