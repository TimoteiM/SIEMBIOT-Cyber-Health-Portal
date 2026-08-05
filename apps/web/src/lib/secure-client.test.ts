import { beforeEach, describe, expect, it, vi } from "vitest";

import { apiRequest, loadSession } from "./secure-client";

describe("secure API client", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("sends same-origin credentials and never caches a private response", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          contract_version: "v1",
          authenticated: true,
          user: { id: crypto.randomUUID(), email: "user@example.test", display_name: "Test" },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    await loadSession();

    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      credentials: "same-origin",
      cache: "no-store",
    });
  });

  it("carries no bearer token or CSRF header of its own", async () => {
    // Authentication terminates upstream, so this client holds no credential. Anything
    // that authenticates the request is attached by the layer in front of it.
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ contract_version: "v1", id: crypto.randomUUID() }), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await apiRequest("/api/v1/organizations", {
      method: "POST",
      body: JSON.stringify({ name: "Exemplu", slug: "exemplu" }),
    });

    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers);
    expect(headers.has("X-CSRF-Token")).toBe(false);
    expect(headers.has("Authorization")).toBe(false);
    expect(headers.get("Content-Type")).toBe("application/json");
  });

  it("returns the generic API error without exposing response internals", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          contract_version: "v1",
          error: {
            code: "forbidden",
            message: "Operațiunea nu este permisă.",
            request_id: "A".repeat(26),
          },
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
