import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      encryptTransit: vi.fn(async () => ({ ciphertext: "CIPHER", version: 1 })),
      decryptTransit: vi.fn(async () => ({ plaintext: btoa("hello") })),
    },
  };
});

import { TransitConsole } from "@/components/secrets/transit";

describe("U2-9 transit console", () => {
  it("round-trips encrypt then decrypt through the served transit API", async () => {
    render(<TransitConsole />);
    await userEvent.type(screen.getByPlaceholderText("transit-key-1"), "k1");
    await userEvent.type(screen.getByRole("textbox", { name: "Plaintext" }), "hello");
    await userEvent.click(screen.getByRole("button", { name: "Encrypt" }));
    expect(await screen.findByText(/ciphertext: CIPHER/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Decrypt" }));
    expect(await screen.findByText(/decrypted: hello/)).toBeInTheDocument();
  });
});
