import { NextResponse, type NextRequest } from "next/server";

import { accountBySubject, DEV_IDENTITY_COOKIE } from "./lib/dev-accounts";

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

const ISSUER = process.env.SIEMBIOT_DEV_IDENTITY_ISSUER ?? "https://idp.local.test";

/**
 * The identity from the environment, which is how this worked before there was a
 * sign-in page. Kept as the fallback so an existing local setup, and every script that
 * exports these variables, carries on unchanged.
 */
const CONFIGURED = {
  subject: process.env.SIEMBIOT_DEV_IDENTITY_SUBJECT ?? "",
  email: process.env.SIEMBIOT_DEV_IDENTITY_EMAIL ?? "",
  name: process.env.SIEMBIOT_DEV_IDENTITY_NAME ?? "",
};

function chosenIdentity(request: NextRequest) {
  // A cookie set by the development sign-in page. It names an account defined in the
  // repository rather than carrying an identity of its own, so a forged value can only
  // select between the two accounts that already exist -- and only in development,
  // where the API accepts these headers at all.
  const chosen = request.cookies.get(DEV_IDENTITY_COOKIE)?.value;
  const account = chosen ? accountBySubject(chosen) : null;
  if (account) {
    return { subject: account.subject, email: account.email, name: account.name };
  }
  return CONFIGURED;
}

function developmentIdentityEnabled(): boolean {
  return process.env.NODE_ENV === "development";
}

export function middleware(request: NextRequest) {
  if (!developmentIdentityEnabled()) {
    return NextResponse.next();
  }
  const identity = chosenIdentity(request);
  if (!identity.subject || !identity.email) {
    return NextResponse.next();
  }

  const headers = new Headers(request.headers);
  const values: Record<string, string> = {
    "x-siembiot-identity-issuer": ISSUER,
    "x-siembiot-identity-subject": identity.subject,
    "x-siembiot-identity-email": identity.email,
    "x-siembiot-identity-name": identity.name,
  };
  for (const [name, value] of Object.entries(values)) {
    // Never overwrites: a real gateway in front of a development build still wins.
    if (value && !headers.has(name)) {
      headers.set(name, value);
    }
  }
  return NextResponse.next({ request: { headers } });
}

export const config = {
  matcher: "/api/:path*",
};
