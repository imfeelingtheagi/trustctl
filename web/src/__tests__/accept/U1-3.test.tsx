import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ReadinessSimulator } from "@/components/certs";
import type { Certificate } from "@/lib/api";

function cert(id: string): Certificate {
  return { id, subject: id, status: "active", fingerprint: id } as unknown as Certificate;
}

describe("U1-3 47-day readiness simulator", () => {
  it("recomputes renewal load and lapse risk as the validity cap changes", async () => {
    const certificates = Array.from({ length: 10 }, (_unused, index) => cert(`c${index}`));

    render(<ReadinessSimulator certificates={certificates} autoRenewing={6} />);

    // default cap = 47 days: ceil(365/47) = 8 renewals/yr, 4 manual * 8 = 32 load, 4 would lapse
    expect(screen.getByText("8")).toBeInTheDocument();
    expect(screen.getByText("32")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "200-day" }));
    // cap = 200: ceil(365/200) = 2 renewals/yr, 4 manual * 2 = 8 load
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("8")).toBeInTheDocument();
  });
});
