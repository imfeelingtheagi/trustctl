import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { api } from "@/lib/api";

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn(async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("U2-6 dynamic secrets served wiring", () => {
  it("issues and revokes a dynamic lease against the served lease API", async () => {
    await api.issueDynamicLease({ provider: "postgres", role: "readonly", ttl_seconds: 3600 });
    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/v1/secrets/leases");
    expect((fetchMock.mock.calls[0][1] as RequestInit).method).toBe("POST");
    await api.revokeDynamicLease("lease-1");
    expect(String(fetchMock.mock.calls.at(-1)?.[0])).toContain("/api/v1/secrets/leases/lease-1/revoke");
  });
});
