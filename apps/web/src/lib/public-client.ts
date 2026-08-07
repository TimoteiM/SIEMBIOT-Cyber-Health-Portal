/**
 * Reading the observatory from a server component.
 *
 * Separate from `secure-client` on purpose. That one carries session cookies and CSRF
 * handling because every route it touches is authenticated; none of that belongs here,
 * and sending a session cookie to a public endpoint would be the beginning of a page
 * that renders differently for a signed-in reader than for anybody else.
 *
 * A failure returns `null` rather than throwing. The observatory being unreachable is a
 * page that should say so, not a 500: a visitor who came to look up an institution is
 * better served by "this is temporarily unavailable" than by an error screen.
 */

const API_BASE_URL = process.env.SIEMBIOT_API_BASE_URL ?? "http://127.0.0.1:8000";

export async function fetchPublic<T>(path: string): Promise<T | null> {
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      headers: { Accept: "application/json" },
      // Never cached here either. The API says `no-store` so that withdrawing consent
      // takes effect on the next read; caching it in the renderer would put the window
      // back that the API deliberately removed.
      cache: "no-store",
    });
    if (!response.ok) return null;
    return (await response.json()) as T;
  } catch {
    return null;
  }
}
