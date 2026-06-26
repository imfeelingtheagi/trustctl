import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { api } from "@/lib/api";

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn(async () => new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
  vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => vi.unstubAllGlobals());

describe("U3-5 workload + agent broker served wiring", () => {
  it("issues attested SVIDs, broker identities, and ephemeral keys against served endpoints", async () => {
    await api.issueBrokerAgentIdentity(undefined as never);
    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/v1/broker/agent-identities");
    await api.issueAttestedSVID(undefined as never);
    expect(String(fetchMock.mock.calls.at(-1)?.[0])).toContain("/api/v1/workloads/attested-issuance");
    await api.issueEphemeralAPIKey(undefined as never);
    expect(String(fetchMock.mock.calls.at(-1)?.[0])).toContain("/api/v1/ephemeral/api-keys");
  });
});
