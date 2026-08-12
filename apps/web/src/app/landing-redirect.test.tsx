import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import LandingPage from "./page";
import { currentDevAccount, DEV_IDENTITY_COOKIE, SIGNED_IN_HOME } from "../lib/dev-accounts";

/**
 * Where the application opens.
 *
 * Two properties, and the second is the one that is easy to lose. Opening with no
 * identity must land on sign-in rather than a hero whose only purpose is to be clicked
 * through. And opening *with* an identity must not: bouncing somebody who is already
 * signed in back to a sign-in page reads as the session having been dropped, and it is
 * the failure mode a naive "always redirect to login" produces.
 */

const redirect = vi.fn((destination: string) => {
  // The real `redirect` throws to unwind rendering. Imitated, so a page that carried on
  // rendering after redirecting would fail here rather than quietly returning markup
  // nobody sees.
  throw new Error(`REDIRECT:${destination}`);
});
let cookieHeader = "";

vi.mock("next/navigation", () => ({ redirect: (to: string) => redirect(to) }));
vi.mock("next/headers", () => ({
  // Present because the locale resolver reaches for it on the production branch. The
  // redirect happens first in development, so nothing here reads it -- but a mock
  // missing an export fails at import rather than at use.
  headers: async () => ({ get: () => null }),
  cookies: async () => ({
    get: (name: string) => {
      const match = new RegExp(`(?:^|;\\s*)${name}=([^;]*)`).exec(cookieHeader);
      return match ? { name, value: match[1] } : undefined;
    },
  }),
}));

async function destinationOf(): Promise<string> {
  try {
    await LandingPage();
  } catch (error) {
    return String((error as Error).message).replace("REDIRECT:", "");
  }
  return "(rendered, no redirect)";
}

describe("the page the application opens on", () => {
  beforeEach(() => {
    redirect.mockClear();
    cookieHeader = "";
    // Under vitest `NODE_ENV` is "test", so without this the development branch never
    // runs and every assertion below passes by never reaching the code it is about.
    vi.stubEnv("NODE_ENV", "development");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("sends a visitor with no identity to sign in", async () => {
    expect(await destinationOf()).toBe("/sign-in");
  });

  it("sends a visitor who already chose an identity into the application", async () => {
    cookieHeader = `${DEV_IDENTITY_COOKIE}=platform-admin`;
    expect(await destinationOf()).toBe(SIGNED_IN_HOME);
  });

  it("treats a cookie naming no known account as not signed in", async () => {
    // A value left over from a renamed or removed account. Following it would carry
    // somebody into the application under an identity the API rejects, and the failure
    // would surface pages later as an unexplained 401 rather than here as a sign-in.
    cookieHeader = `${DEV_IDENTITY_COOKIE}=an-account-that-was-deleted`;
    expect(await destinationOf()).toBe("/sign-in");
  });

  it("also opens on sign-in in a production build", async () => {
    // The first page a person meets is the sign-in page in every build. What differs is
    // what that page says: a deployment terminates identity at a gateway, so `/sign-in`
    // there states that authentication already happened and renders no form. The
    // redirect is therefore safe to keep, and the honesty lives on the page rather than
    // in whether the redirect survives the build.
    vi.stubEnv("NODE_ENV", "production");
    expect(await destinationOf()).toBe("/sign-in");
  });

  it("does not read the identity cookie in a production build", async () => {
    // There is no cookie worth reading: the middleware that acts on it never runs
    // outside development. Following it would send somebody to the application under an
    // identity the API rejects, which surfaces later as an unexplained 401 -- the exact
    // failure the known-account check exists to prevent in development.
    vi.stubEnv("NODE_ENV", "production");
    cookieHeader = `${DEV_IDENTITY_COOKIE}=platform-admin`;
    expect(await destinationOf()).toBe("/sign-in");
  });
});

describe("reading back which identity is in use", () => {
  it("finds the account among other cookies", async () => {
    const account = currentDevAccount(`locale=ro; ${DEV_IDENTITY_COOKIE}=demo-primar; other=1`);
    expect(account?.username).toBe("expert");
  });

  it("does not match a cookie whose name merely ends with the same text", async () => {
    // `x-siembiot-dev-identity=admin` must not be read as the identity cookie.
    expect(currentDevAccount(`x-${DEV_IDENTITY_COOKIE}=platform-admin`)).toBeNull();
  });

  it("returns nothing when no identity has been chosen", async () => {
    expect(currentDevAccount("locale=en")).toBeNull();
  });
});
