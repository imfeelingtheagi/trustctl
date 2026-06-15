import { describe, it, expect, vi, afterEach } from "vitest";
import { api, ApiError, UnauthorizedError } from "@/lib/api";

// Unit tests for the typed REST client's error handling, focused on the SURFACE-007
// 429/Retry-After path. We stub global fetch so no network is touched.

function mockFetch(status: number, body: string, headers: Record<string, string> = {}) {
  const h = new Headers(headers);
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      new Response(status === 204 ? null : body, { status, headers: h }),
    ),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("api error handling (SURFACE-007)", () => {
  it("maps 401 to UnauthorizedError", async () => {
    mockFetch(401, "no");
    await expect(api.certificates()).rejects.toBeInstanceOf(UnauthorizedError);
  });

  it("surfaces a 429 as a rate-limited ApiError with Retry-After seconds", async () => {
    mockFetch(429, "slow down", { "Retry-After": "30" });
    const err = await api.certificates().catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(429);
    expect((err as ApiError).isRateLimited).toBe(true);
    expect((err as ApiError).retryAfterSeconds).toBe(30);
    expect((err as ApiError).message).toMatch(/retry in 30s/);
  });

  it("parses a 429 Retry-After HTTP-date into seconds", async () => {
    const tenSecondsOut = new Date(Date.now() + 10_000).toUTCString();
    mockFetch(429, "slow down", { "Retry-After": tenSecondsOut });
    const err = (await api.certificates().catch((e) => e)) as ApiError;
    expect(err.status).toBe(429);
    // Allow a little clock slack around the 10s target.
    expect(err.retryAfterSeconds).toBeGreaterThanOrEqual(8);
    expect(err.retryAfterSeconds).toBeLessThanOrEqual(11);
  });

  it("a 429 without Retry-After is still rate-limited (no seconds)", async () => {
    mockFetch(429, "slow down");
    const err = (await api.certificates().catch((e) => e)) as ApiError;
    expect(err.isRateLimited).toBe(true);
    expect(err.retryAfterSeconds).toBeUndefined();
  });

  it("maps other non-2xx to a generic ApiError", async () => {
    mockFetch(500, "boom");
    const err = (await api.certificates().catch((e) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(500);
    expect(err.isRateLimited).toBe(false);
  });
});
