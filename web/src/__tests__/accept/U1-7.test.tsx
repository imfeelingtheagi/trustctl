import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { CAOverview } from "@/components/ca";
import type { Issuer, Profile } from "@/lib/api";

function issuer(partial: Partial<Issuer>): Issuer {
  return { id: "i", name: "CA", kind: "x509_ca", tenant_id: "t", ...partial } as unknown as Issuer;
}
function profile(partial: Partial<Profile>): Profile {
  return { id: "p", name: "web-server", version: 1, active: true, ...partial } as unknown as Profile;
}

describe("U1-7 CA & issuer overview", () => {
  it("summarizes issuers and lists issuance profiles", () => {
    render(
      <CAOverview
        issuers={[issuer({ id: "i1", internal: true }), issuer({ id: "i2", internal: false })]}
        profiles={[profile({ id: "p1", name: "web-server", version: 2 })]}
      />,
    );
    expect(screen.getByText("Issuing CAs")).toBeInTheDocument();
    const list = screen.getByRole("list", { name: "Issuance profiles" });
    expect(within(list).getByText("web-server")).toBeInTheDocument();
    expect(within(list).getByText("v2")).toBeInTheDocument();
  });
});
