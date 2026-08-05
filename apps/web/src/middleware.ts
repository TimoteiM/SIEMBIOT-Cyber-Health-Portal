import { NextResponse, type NextRequest } from "next/server";

/**
 * Development-only identity injection.
 *
 * Authentication is owned by a separate team and terminates upstream. In a real
 * deployment their gateway injects the identity headers before a request reaches this
 * application. Locally there is no gateway, so a browser would otherwise have no way
 * to present an identity and every page would sit at 401.
 *
 * This middleware fills that gap for local work only. It is gated three ways, and all
 * three must hold:
 *
 *   1. `NODE_ENV` is exactly "development" — a production build never runs this path.
 *   2. `SIEMBIOT_DEV_IDENTITY_SUBJECT` is explicitly set — absent means no injection.
 *   3. It never overwrites headers that are already present, so a real gateway in
 *      front of a development build still wins.
 *
 * It also injects no gateway proof, so the API's production resolver would reject
 * these headers anyway. The bypass therefore cannot survive a real deployment even if
 * this file were somehow reached.
 */

const IDENTITY_HEADERS = {
  "x-siembiot-identity-issuer": process.env.SIEMBIOT_DEV_IDENTITY_ISSUER ?? "https://idp.local.test",
  "x-siembiot-identity-subject": process.env.SIEMBIOT_DEV_IDENTITY_SUBJECT ?? "",
  "x-siembiot-identity-email": process.env.SIEMBIOT_DEV_IDENTITY_EMAIL ?? "",
  "x-siembiot-identity-name": process.env.SIEMBIOT_DEV_IDENTITY_NAME ?? "",
} as const;

function developmentIdentityEnabled(): boolean {
  return (
    process.env.NODE_ENV === "development" &&
    Boolean(IDENTITY_HEADERS["x-siembiot-identity-subject"]) &&
    Boolean(IDENTITY_HEADERS["x-siembiot-identity-email"])
  );
}

export function middleware(request: NextRequest) {
  if (!developmentIdentityEnabled()) {
    return NextResponse.next();
  }

  const headers = new Headers(request.headers);
  for (const [name, value] of Object.entries(IDENTITY_HEADERS)) {
    if (value && !headers.has(name)) {
      headers.set(name, value);
    }
  }
  return NextResponse.next({ request: { headers } });
}

export const config = {
  matcher: "/api/:path*",
};
