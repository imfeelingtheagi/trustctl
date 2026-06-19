import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Policy } from "@/pages/Policy";

function renderPolicy() {
  return render(
    <MemoryRouter>
      <Policy />
    </MemoryRouter>,
  );
}

describe("policy governance surface", () => {
  it("explains served policy outcomes and keeps authoring/dry-run honestly blocked", () => {
    renderPolicy();

    expect(screen.getByRole("heading", { name: "Policy" })).toBeInTheDocument();
    expect(screen.getByText("Allowed")).toBeInTheDocument();
    expect(screen.getByText("Denied")).toBeInTheDocument();
    expect(screen.getByText("Policy error")).toBeInTheDocument();
    expect(screen.getByText("Overload 503")).toBeInTheDocument();
    expect(screen.getByText(/default-deny wins/i)).toBeInTheDocument();
    expect(screen.getByText(/policy.decision deny/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Audit policy decisions/i })).toHaveAttribute(
      "href",
      "/audit?type=policy.decision",
    );
    expect(screen.getByRole("link", { name: /profile evaluation evidence/i })).toHaveAttribute(
      "href",
      "/audit?type=issuance.profile_evaluated",
    );
    expect(screen.getByText("Policy authoring and dry-run API not served yet")).toBeInTheDocument();
    expect(screen.getByText(/BACKEND-POLICY-AUTHOR/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /dry run/i })).not.toBeInTheDocument();
  });
});
