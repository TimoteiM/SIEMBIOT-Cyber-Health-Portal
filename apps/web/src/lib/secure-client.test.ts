import { beforeEach, describe, expect, it, vi } from "vitest";

import { apiRequest, loadSession, resetSessionMemoryForTests } from "./secure-client";

describe("secure API client", () => {
  beforeEach(() => {
    resetSessionMemoryForTests();
    vi.restoreAllMocks();
  });

  it("keeps the CSRF value in memory and sends same-origin cookies", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            contract_version: "v1",
            authenticated: true,
            user: { id: crypto.randomUUID(), email: "user@example.test", display_name: "Test" },
            expires_at: "2026-08-03T12:00:00Z",
            csrf_token: "memory-only-csrf-token-value",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ contract_version: "v1", id: crypto.randomUUID() }), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        }),
      );

    await loadSession();
    await apiRequest("/api/v1/organizations", {
      method: "POST",
      body: JSON.stringify({ name: "Exemplu", slug: "exemplu" }),
    });

    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({ credentials: "same-origin" });
    expect(fetchMock.mock.calls[1]?.[1]).toMatchObject({ credentials: "same-origin" });
    const headers = new Headers(fetchMock.mock.calls[1]?.[1]?.headers);
    expect(headers.get("X-CSRF-Token")).toBe("memory-only-csrf-token-value");
  });

  it("does not attach a CSRF header to safe methods", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    await apiRequest("/api/v1/organizations");
    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers);
    expect(headers.has("X-CSRF-Token")).toBe(false);
  });

  it("returns the generic API error without exposing response internals", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          contract_version: "v1",
          error: { code: "forbidden", message: "Operațiunea nu este permisă.", request_id: "A".repeat(26) },
        }),
        { status: 403, headers: { "Content-Type": "application/json" } },
      ),
    );
    await expect(apiRequest("/api/v1/organizations/denied")).rejects.toMatchObject({
      code: "forbidden",
      status: 403,
    });
  });
});
