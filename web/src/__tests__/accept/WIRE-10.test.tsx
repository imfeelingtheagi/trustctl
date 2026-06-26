import { readFileSync } from "node:fs";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Protocols } from "@/pages/Protocols";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    protocolStatuses: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderProtocols() {
  return render(
    <MemoryRouter>
      <Protocols />
    </MemoryRouter>,
  );
}

describe("WIRE-10 protocol responder status wiring", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.protocolStatuses.mockReset();
    apiMock.protocolStatuses.mockResolvedValue({
      source: "public_responder_probe",
      checked_at: "2026-06-26T14:00:00Z",
      items: [
        {
          protocol: "acme",
          endpoint: "/directory",
          enabled: true,
          served: true,
          status_code: 200,
          detail: "ACME directory responded.",
        },
        {
          protocol: "scep",
          endpoint: "/scep?operation=GetCACaps",
          enabled: false,
          served: false,
          status_code: 404,
          detail: "SCEP responder is not mounted.",
        },
        {
          protocol: "tsa",
          endpoint: "/tsa",
          enabled: true,
          served: true,
          status_code: 405,
          detail: "TSA route is mounted and expects a timestamp request.",
        },
      ],
    });
  });

  it("renders live enabled and off state from the served responder-status client", async () => {
    renderProtocols();

    await waitFor(() => expect(apiMock.protocolStatuses).toHaveBeenCalledTimes(1));

    const acmeRow = within(screen.getByRole("row", { name: /ACME ACME directory/i }));
    expect(acmeRow.getByText("Enabled")).toBeInTheDocument();
    expect(acmeRow.getByText("/directory")).toBeInTheDocument();
    expect(acmeRow.getByText("HTTP 200")).toBeInTheDocument();

    const scepRow = within(screen.getByRole("row", { name: /SCEP SCEP CA discovery/i }));
    expect(scepRow.getByText("Off")).toBeInTheDocument();
    expect(scepRow.getByText("/scep?operation=GetCACaps")).toBeInTheDocument();
    expect(scepRow.getByText("HTTP 404")).toBeInTheDocument();

    const tsaRow = within(screen.getByRole("row", { name: /TSA RFC 3161/i }));
    expect(tsaRow.getByText("Served")).toBeInTheDocument();
    expect(tsaRow.getByText("/tsa")).toBeInTheDocument();
    expect(tsaRow.getByText("HTTP 405")).toBeInTheDocument();

    expect(screen.queryByText("Status unknown to console")).not.toBeInTheDocument();
    expect(screen.queryByText("Live enabled-state coming soon")).not.toBeInTheDocument();
  });

  it("removes the blanket unknown protocol-status fixture", () => {
    const source = readFileSync(path.join(process.cwd(), "src/pages/Protocols.tsx"), "utf8");
    expect(source).not.toMatch(/Status unknown to console/);
    expect(source).not.toMatch(/Live enabled-state coming soon/);
  });
});
