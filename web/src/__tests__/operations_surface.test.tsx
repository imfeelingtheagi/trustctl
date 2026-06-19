import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/lib/api";
import { ThemeProvider } from "@/components/ThemeProvider";
import { AuthProvider } from "@/auth/AuthProvider";
import { AppRoutes } from "@/App";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    me: vi.fn(),
    profiles: vi.fn(),
    getProfileVersion: vi.fn(),
    createProfile: vi.fn(),
    auditEvents: vi.fn(),
    exportAudit: vi.fn(),
    graph: vi.fn(),
    graphBlastRadius: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderAt(path: string) {
  return render(
    <ThemeProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <AppRoutes />
        </MemoryRouter>
      </AuthProvider>
    </ThemeProvider>,
  );
}

describe("operational console surface", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.me.mockResolvedValue({ subject: "user-1", tenant_id: "t1", email: "u@example.test" });
  });

  it("routes to profiles, lists versions, and creates a profile", async () => {
    apiMock.profiles
      .mockResolvedValueOnce([{ id: "p1", name: "server", version: 1, active: true, created_by: "ra" }])
      .mockResolvedValueOnce([{ id: "p2", name: "server", version: 2, active: true, created_by: "ra" }]);
    apiMock.createProfile.mockResolvedValue({ id: "p1", name: "server", version: 2, active: true });
    const user = userEvent.setup();
    renderAt("/profiles");

    expect(await screen.findByRole("heading", { name: "Profiles" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Profiles/i })).toHaveAttribute("href", "/profiles");
    expect(await screen.findByText("server")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /New profile/i }));
    await user.clear(screen.getByLabelText(/Profile name/i));
    await user.type(screen.getByLabelText(/Profile name/i), "server");
    await user.click(screen.getByRole("button", { name: /Create profile/i }));

    await waitFor(() =>
      expect(apiMock.createProfile).toHaveBeenCalledWith({
        name: "server",
        spec: {
          allowed_key_algorithms: ["ECDSA"],
          min_ecdsa_bits: 256,
          allowed_ekus: ["serverAuth"],
          max_validity: "2160h",
          allowed_protocols: ["api", "acme"],
          allowed_dns_suffixes: ["example.com"],
        },
      }),
    );
  });

  it("surfaces served profile validation problems from the JSON fallback", async () => {
    apiMock.profiles.mockResolvedValue([]);
    apiMock.createProfile.mockRejectedValue(
      new ApiError(422, JSON.stringify({ detail: "max_validity exceeds the tenant profile ceiling" })),
    );
    const user = userEvent.setup();
    renderAt("/profiles");

    await user.click(await screen.findByRole("button", { name: /New profile/i }));
    await user.type(screen.getByLabelText(/Profile name/i), "oversized");
    await user.click(screen.getByRole("button", { name: /JSON editor/i }));
    fireEvent.change(screen.getByLabelText(/JSON spec/i), {
      target: { value: '{"max_validity":"999999h"}' },
    });
    await user.click(screen.getByRole("button", { name: /Create profile/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("max_validity exceeds the tenant profile ceiling");
  });

  it("loads concrete profile versions and diffs selected rules against the active version", async () => {
    const versionOne = {
      id: "p1",
      name: "server",
      version: 1,
      active: false,
      created_by: "ra",
      spec: {
        allowed_key_algorithms: ["RSA"],
        min_rsa_bits: 2048,
        allowed_ekus: ["serverAuth"],
        max_validity: "720h",
      },
    };
    const versionTwo = {
      id: "p2",
      name: "server",
      version: 2,
      active: true,
      created_by: "ra",
      spec: {
        allowed_key_algorithms: ["ECDSA"],
        min_ecdsa_bits: 256,
        allowed_ekus: ["serverAuth"],
        max_validity: "2160h",
        allowed_dns_suffixes: ["example.com"],
      },
    };
    apiMock.profiles.mockResolvedValue([versionOne, versionTwo]);
    apiMock.getProfileVersion.mockImplementation((_name: string, version: number) =>
      Promise.resolve(version === 1 ? versionOne : versionTwo),
    );
    const user = userEvent.setup();
    renderAt("/profiles");

    await user.click(await screen.findByRole("button", { name: "View server version 1" }));
    expect(await screen.findByRole("heading", { name: "server version 1" })).toBeInTheDocument();
    expect(screen.getByText(/does not rewrite past decisions/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Diff version/i }));

    await waitFor(() => expect(apiMock.getProfileVersion).toHaveBeenCalledWith("server", 2));
    expect(await screen.findByText(/Comparing selected v1 to v2/i)).toBeInTheDocument();
    expect(screen.getByText("max_validity")).toBeInTheDocument();
    expect(screen.getAllByText("Changed").length).toBeGreaterThan(0);
  });

  it("routes to audit events and exports signed evidence", async () => {
    apiMock.auditEvents.mockResolvedValue([
      { sequence: 7, id: "evt-7", type: "identity.issued", tenant_id: "t1", time: "2026-06-17T12:00:00Z", hash: "abc" },
    ]);
    apiMock.exportAudit.mockResolvedValue({ format: "jws", bundle: "sealed.bundle" });
    const user = userEvent.setup();
    renderAt("/audit");

    expect(await screen.findByRole("heading", { name: "Audit" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Audit/i })).toHaveAttribute("href", "/audit");
    expect(await screen.findByText("identity.issued")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Export evidence/i }));
    expect(await screen.findByText("jws: sealed.bundle")).toBeInTheDocument();
    expect(apiMock.exportAudit).toHaveBeenCalledTimes(1);
  });

  it("routes to graph inventory and runs blast-radius analysis", async () => {
    apiMock.graph.mockResolvedValue({
      nodes: [
        { id: "cert:1", kind: "credential", name: "payments-cert" },
        { id: "res:1", kind: "resource", name: "payments-api" },
      ],
      edges: [{ from: "cert:1", to: "res:1", type: "DEPLOYED_TO" }],
    });
    apiMock.graphBlastRadius.mockResolvedValue({
      node: { id: "cert:1", kind: "credential", name: "payments-cert" },
      affected: [{ id: "res:1", kind: "resource", name: "payments-api" }],
      by_kind: {},
    });
    const user = userEvent.setup();
    renderAt("/graph");

    expect(await screen.findByRole("heading", { name: "Graph" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Graph/i })).toHaveAttribute("href", "/graph");
    expect((await screen.findAllByText("payments-cert")).length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: /Analyze/i }));
    await waitFor(() => expect(apiMock.graphBlastRadius).toHaveBeenCalledWith("cert:1"));
    expect(screen.getByTestId("blast-radius-count")).toHaveTextContent("1");
  });
});
