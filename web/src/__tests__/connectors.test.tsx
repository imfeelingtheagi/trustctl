import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Connectors } from "@/pages/Connectors";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    connectorCatalog: vi.fn(),
    connectorDeliveries: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderConnectors() {
  return render(
    <MemoryRouter>
      <Connectors />
    </MemoryRouter>,
  );
}

describe("connector deployment disclosure surface", () => {
  beforeEach(() => {
    apiMock.connectorCatalog.mockReset().mockResolvedValue({
      items: [
        { name: "nginx", kind: "file/process", delivery_mode: "signed plugin or connector outbox receipt", rollback: "restore previous fullchain/key pair and reload nginx" },
        { name: "apache", kind: "file/process", delivery_mode: "signed plugin or connector outbox receipt", rollback: "restore previous SSLCertificateFile and graceful reload" },
        { name: "haproxy", kind: "file/process", delivery_mode: "signed plugin or connector outbox receipt", rollback: "restore previous bundle and reload HAProxy" },
        { name: "iis", kind: "windows", delivery_mode: "signed plugin or connector outbox receipt", rollback: "restore previous binding thumbprint" },
        { name: "aws-acm", kind: "cloud", delivery_mode: "signed plugin or connector outbox receipt", rollback: "repoint listener to previous ACM ARN" },
        { name: "azure-keyvault", kind: "cloud", delivery_mode: "signed plugin or connector outbox receipt", rollback: "reactivate prior certificate version" },
        { name: "gcp-certificate-manager", kind: "cloud", delivery_mode: "signed plugin or connector outbox receipt", rollback: "reattach prior certificate resource" },
        { name: "java-keystore", kind: "keystore", delivery_mode: "signed plugin or connector outbox receipt", rollback: "restore previous keystore object" },
        { name: "f5", kind: "appliance", delivery_mode: "signed plugin or connector outbox receipt", rollback: "swap virtual server back to previous cert/key object" },
        { name: "netscaler", kind: "appliance", delivery_mode: "signed plugin or connector outbox receipt", rollback: "bind previous certKey to the service group" },
        { name: "cisco", kind: "appliance", delivery_mode: "signed plugin or connector outbox receipt", rollback: "restore previous trustpoint binding" },
        { name: "fortigate", kind: "appliance", delivery_mode: "signed plugin or connector outbox receipt", rollback: "restore previous local certificate reference" },
        { name: "paloalto", kind: "appliance", delivery_mode: "signed plugin or connector outbox receipt", rollback: "revert candidate config to prior certificate object" },
      ],
    });
    apiMock.connectorDeliveries.mockReset().mockResolvedValue({
      items: [
        {
          id: "receipt-1",
          tenant_id: "tenant-1",
          identity_id: "identity-1",
          destination: "connector.deploy",
          connector: "nginx",
          target: "edge-1",
          fingerprint: "abc123",
          status: "unrouted",
          attempts: 1,
          reason: "plugin_not_loaded",
          detail: "connector is not owned by a loaded signed plugin",
          rollback_ref: "",
          idempotency_key: "event-1",
          created_at: "2026-06-20T00:00:00Z",
          updated_at: "2026-06-20T00:00:00Z",
        },
      ],
    });
  });

  it("renders served connector registry, receipts, fixture grants, and outbox state without live deploy controls", async () => {
    renderConnectors();

    expect(screen.getByRole("heading", { name: "Deployment connectors" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Served connector registry" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.connectorCatalog).toHaveBeenCalled());
    expect(apiMock.connectorDeliveries).toHaveBeenCalledWith({ limit: 20 });
    for (const target of [
      "nginx",
      "apache",
      "haproxy",
      "iis",
      "aws-acm",
      "azure-keyvault",
      "gcp-certificate-manager",
      "java-keystore",
      "netscaler",
      "paloalto",
    ]) {
      expect(screen.getAllByText(target).length).toBeGreaterThan(0);
    }
    expect(screen.getByRole("heading", { name: "Recent delivery receipts" })).toBeInTheDocument();
    expect(screen.getByText("plugin_not_loaded")).toBeInTheDocument();
    expect(screen.getByText("edge-1")).toBeInTheDocument();
    expect(screen.getAllByText(/connector\.deploy/).length).toBeGreaterThan(0);
    expect(screen.getByText("secret://connectors/aws-acm/prod:****")).toBeInTheDocument();
    expect(screen.getAllByText(/dry-run|test-deploy/i).length).toBeGreaterThan(0);
    expect(screen.getByText("delivered")).toBeInTheDocument();
    expect(screen.getAllByText("unrouted").length).toBeGreaterThan(0);
    expect(screen.queryByText(/BEGIN .* PRIVATE KEY/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /deploy|dry run|test deploy|rollback/i })).not.toBeInTheDocument();
  });

  it("renders appliance connector reachability and rollback fixtures without target credentials", async () => {
    renderConnectors();

    expect(await screen.findByRole("heading", { name: "Served connector registry" })).toBeInTheDocument();
    for (const target of ["F5 BIG-IP", "NetScaler", "Cisco", "FortiGate", "Palo Alto"]) {
      expect(screen.getByText(target)).toBeInTheDocument();
    }
    expect(screen.getByText(/management endpoint reachable/)).toBeInTheDocument();
    expect(screen.getByText(/RESTCONF or SSH transport reachable/)).toBeInTheDocument();
    expect(screen.getAllByText(/rollback|restore|revert/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/raw token hidden/i)).toBeInTheDocument();
  });
});
