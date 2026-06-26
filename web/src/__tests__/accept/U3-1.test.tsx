import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { NhiInventory } from "@/components/nhi";
import type { Identity, CredentialRisk } from "@/lib/api";

const identities = [
  { id: "i1", name: "payments-worker", kind: "workload_identity", owner_id: "team-pay", status: "issued" },
  { id: "i2", name: "ci-runner", kind: "agent", status: "issued" },
] as unknown as Identity[];
const risks = [{ credential_id: "i1", score: 82 }] as unknown as CredentialRisk[];

describe("U3-1 unified NHI inventory", () => {
  it("summarizes machine identities by type with a risk lens", () => {
    render(<NhiInventory identities={identities} risks={risks} />);
    expect(screen.getByText("Total identities")).toBeInTheDocument();
    expect(screen.getByText("Workload identity")).toBeInTheDocument();
    expect(screen.getByText("Agent")).toBeInTheDocument();
    expect(screen.getByText("High risk")).toBeInTheDocument();
  });
});
