import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { Certificates } from "@/pages/Certificates";

const { apiMock } = vi.hoisted(() => ({
  apiMock: { certificates: vi.fn() },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function renderCerts() {
  return render(
    <MemoryRouter>
      <Certificates />
    </MemoryRouter>,
  );
}

describe("inventory search", () => {
  beforeEach(() => apiMock.certificates.mockReset());

  it("filters the certificate inventory as you type", async () => {
    apiMock.certificates.mockResolvedValue([
      { id: "c1", subject: "CN=payments.example.com", issuer: "CN=CA", status: "active" },
      { id: "c2", subject: "CN=web.example.com", issuer: "CN=CA", status: "active" },
    ]);
    const user = userEvent.setup();
    renderCerts();

    expect(await screen.findByText("CN=payments.example.com")).toBeInTheDocument();
    expect(screen.getByText("CN=web.example.com")).toBeInTheDocument();

    await user.type(screen.getByRole("searchbox", { name: /search/i }), "payments");

    await waitFor(() => expect(screen.queryByText("CN=web.example.com")).not.toBeInTheDocument());
    expect(screen.getByText("CN=payments.example.com")).toBeInTheDocument();
  });

  it("reports when a search matches nothing", async () => {
    apiMock.certificates.mockResolvedValue([{ id: "c1", subject: "CN=payments.example.com" }]);
    const user = userEvent.setup();
    renderCerts();

    await screen.findByText("CN=payments.example.com");
    await user.type(screen.getByRole("searchbox", { name: /search/i }), "nomatch");
    expect(await screen.findByText(/no (certificates )?match/i)).toBeInTheDocument();
  });
});

describe("guiding empty states", () => {
  beforeEach(() => apiMock.certificates.mockReset());

  it("guides a fresh install to the setup wizard when the inventory is empty", async () => {
    apiMock.certificates.mockResolvedValue([]);
    renderCerts();

    const cta = await screen.findByRole("link", { name: /set up|get started|first certificate|wizard/i });
    expect(cta).toHaveAttribute("href", expect.stringContaining("/wizard"));
  });
});
