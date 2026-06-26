import { describe, it, expect, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SecretTree, groupSecretsByFolder } from "@/components/secrets";
import type { SecretMeta } from "@/lib/api";

const secrets = [
  { name: "prod/db/password", version: 1 },
  { name: "prod/db/user", version: 1 },
  { name: "prod/api/key", version: 1 },
  { name: "flat", version: 1 },
] as SecretMeta[];

describe("U2-1 secret folder tree", () => {
  it("groups secret names into folders by path", () => {
    const folders = groupSecretsByFolder(secrets);
    const byPath = Object.fromEntries(folders.map((folder) => [folder.path, folder.secrets.length]));
    expect(byPath["prod/db"]).toBe(2);
    expect(byPath["prod/api"]).toBe(1);
    expect(byPath["/"]).toBe(1);
  });

  it("renders folders with leaf secrets and selects on click", async () => {
    const onSelect = vi.fn();
    render(<SecretTree secrets={secrets} onSelect={onSelect} />);
    const nav = screen.getByRole("navigation", { name: "Secret folders" });
    expect(within(nav).getByText("prod/db")).toBeInTheDocument();
    expect(within(nav).getByText("prod/api")).toBeInTheDocument();
    expect(within(nav).getByText("(root)")).toBeInTheDocument();
    await userEvent.click(within(nav).getByRole("button", { name: "password" }));
    expect(onSelect).toHaveBeenCalledWith("prod/db/password");
  });
});
