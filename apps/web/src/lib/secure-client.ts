import type { components } from "@siembiot/contracts/private-api-v1";

type Session = components["schemas"]["SessionResponse"];
type ErrorEnvelope = {
  error: { code: string; message: string; request_id: string };
};

let csrfToken: string | undefined;

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
  if (isMutation(method)) {
    if (!csrfToken) throw new ApiError("Sesiunea trebuie reîmprospătată.", 401, "csrf_missing");
    headers.set("X-CSRF-Token", csrfToken);
  }
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
      error?.message ?? "Cererea nu a putut fi finalizată.",
      response.status,
      error?.code ?? "request_failed",
      error?.request_id,
    );
  }
  if (response.status === 204) return undefined as T;
  return await response.json() as T;
}

export async function loadSession(): Promise<Session> {
  const session = await apiRequest<Session>("/api/v1/session");
  csrfToken = session.csrf_token;
  return session;
}

export function resetSessionMemoryForTests(): void {
  csrfToken = undefined;
}
