import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, getSecret: vi.fn(async () => ({ name: "prod/db/url", value: "resolved-value", version: 1 })) } };
});

import { ReferenceResolver } from "@/components/secrets";

describe("U2-2 secret references", () => {
  it("resolves a reference through the served resolve path", async () => {
    render(<ReferenceResolver />);
    await userEvent.type(screen.getByPlaceholderText("prod/db/url"), "prod/db/url");
    await userEvent.click(screen.getByRole("button", { name: "Resolve references" }));
    expect(await screen.findByText(/resolved: resolved-value/)).toBeInTheDocument();
  });
});
