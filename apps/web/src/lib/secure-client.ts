import type { components } from "@siembiot/contracts/private-api-v1";

type Session = components["schemas"]["SessionResponse"];
type ErrorEnvelope = {
  error: { code: string; message: string; request_id: string };
};

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function isMutation(method: string): boolean {
  return !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = init.method ?? "GET";
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  const response = await fetch(path, {
    ...init,
    method,
    headers,
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!response.ok) {
    let error: ErrorEnvelope["error"] | undefined;
    try {
      error = (await response.json() as ErrorEnvelope).error;
    } catch {
      error = undefined;
    }
    throw new ApiError(
      // Developer-facing only. Every caller renders a translated sentence from the
      // error code instead; this is what appears in a stack trace.
      error?.message ?? "The request could not be completed.",
      response.status,
      error?.code ?? "request_failed",
      error?.request_id,
    );
  }
  if (response.status === 204) return undefined as T;
  return await response.json() as T;
}

/**
 * Reports who the upstream authentication layer says the caller is.
 *
 * Authentication itself is owned by a separate team and terminates before a request
 * reaches this application, so there is no login flow and no CSRF token to carry here.
 * State-changing requests are same-origin, which the API enforces by origin.
 */
export async function loadSession(): Promise<Session> {
  return await apiRequest<Session>("/api/v1/session");
}
