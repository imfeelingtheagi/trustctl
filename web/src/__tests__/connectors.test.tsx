import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Connectors } from "@/pages/Connectors";

function renderConnectors() {
  return render(
    <MemoryRouter>
      <Connectors />
    </MemoryRouter>,
  );
}

describe("connector deployment disclosure surface", () => {
  it("renders core connector registry, grants, masked references, and outbox state without live deploy controls", () => {
    renderConnectors();

    expect(screen.getByRole("heading", { name: "Deployment connectors" })).toBeInTheDocument();
    for (const target of [
      "nginx",
      "Apache",
      "HAProxy",
      "IIS",
      "AWS ACM",
      "Azure Key Vault",
      "GCP Certificate Manager",
      "Java keystore",
      "Kubernetes",
    ]) {
      expect(screen.getByText(target)).toBeInTheDocument();
    }
    expect(screen.getAllByText(/connector\.deploy/).length).toBeGreaterThan(0);
    expect(screen.getByText("secret://connectors/aws-acm/prod:****")).toBeInTheDocument();
    expect(screen.getAllByText(/dry-run|test-deploy/i).length).toBeGreaterThan(0);
    expect(screen.getByText("acked")).toBeInTheDocument();
    expect(screen.getByText("held")).toBeInTheDocument();
    expect(screen.getAllByText(/Connector deployment runs in the outbox worker today/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/BEGIN .* PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /deploy|dry run|test deploy|rollback/i })).not.toBeInTheDocument();
  });

  it("renders appliance connector reachability and rollback fixtures without target credentials", () => {
    renderConnectors();

    for (const target of ["F5 BIG-IP", "NetScaler", "Cisco", "FortiGate", "Palo Alto"]) {
      expect(screen.getByText(target)).toBeInTheDocument();
    }
    expect(screen.getByText(/management endpoint reachable/)).toBeInTheDocument();
    expect(screen.getByText(/RESTCONF or SSH transport reachable/)).toBeInTheDocument();
    expect(screen.getAllByText(/rollback|restore|revert/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/raw token hidden/i)).toBeInTheDocument();
  });
});
