import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { api } from "@/lib/api";

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn(async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("U2-8 secret scanning and one-time shares served wiring", () => {
  it("scans secrets and creates/redeems shares against the served endpoints", async () => {
    await api.scanSecrets({ path: "/repo" });
    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/v1/secrets/scans");

    await api.createShare({ value: "one-time" });
    expect(String(fetchMock.mock.calls.at(-1)?.[0])).toContain("/api/v1/secrets/shares");

    await api.redeemShare({ token: "abc" });
    expect(String(fetchMock.mock.calls.at(-1)?.[0])).toContain("/api/v1/secrets/shares/redeem");
  });
});
