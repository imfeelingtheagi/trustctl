import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, importSecrets: vi.fn(async () => ({ items: [{ name: "prod/imported/DB_URL", version: 1 }] })) } };
});

import { SecretImport } from "@/components/secrets";

describe("U2-5 secret import", () => {
  it("imports key=value pairs through the served import endpoint", async () => {
    render(<SecretImport />);
    await userEvent.type(screen.getByPlaceholderText("prod/imported"), "prod/imported");
    await userEvent.type(screen.getByPlaceholderText(/DB_URL=/), "DB_URL=postgres://x");
    await userEvent.click(screen.getByRole("button", { name: "Import" }));
    expect(await screen.findByText(/Imported 1 secrets: prod\/imported\/DB_URL/)).toBeInTheDocument();
  });
});
