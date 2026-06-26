import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { RiskPosture } from "@/components/risk/posture";
import type { CredentialRisk } from "@/lib/api";

const risks = [
  { credential_id: "c1", subject: "high-svc", kind: "x509", score: 90, owner_active: true },
  { credential_id: "c2", subject: "low-svc", kind: "secret", score: 12, owner_active: false },
] as unknown as CredentialRisk[];

describe("U3-3 risk posture dashboard", () => {
  it("summarizes scored credentials by band, orphan state, and average — without duplicating subject rows", () => {
    render(<RiskPosture risks={risks} />);
    expect(screen.getByText("Credentials scored")).toBeInTheDocument();
    expect(screen.getByText("Critical (90+)")).toBeInTheDocument();
    expect(screen.getByText("Orphaned")).toBeInTheDocument();
    expect(screen.getByText("Average score")).toBeInTheDocument();
    // (90 + 12) / 2 = 51, rounded.
    expect(screen.getByText("51")).toBeInTheDocument();
    // It must NOT render individual risk subjects (the Risk grid owns those).
    expect(screen.queryByText("high-svc")).not.toBeInTheDocument();
  });
});
