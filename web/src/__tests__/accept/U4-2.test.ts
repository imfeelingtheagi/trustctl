import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { api } from "@/lib/api";

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn(async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("U4-2 discovery sources/runs/findings served wiring", () => {
  it("creates sources, starts runs, and reads findings against served endpoints", async () => {
    await api.createDiscoverySource(undefined as never);
    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/v1/discovery/sources");
    await api.startDiscoveryRun(undefined as never);
    expect(String(fetchMock.mock.calls.at(-1)?.[0])).toContain("/api/v1/discovery/runs");
    await api.discoveryFindings();
    expect(String(fetchMock.mock.calls.at(-1)?.[0])).toContain("/api/v1/discovery/findings");
  });
});
