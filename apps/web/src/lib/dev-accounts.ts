/**
 * The sign-in that exists only because there is no identity provider on a laptop.
 *
 * **This is not authentication and must never be mistaken for it.** Real deployments
 * terminate identity at a gateway upstream of this application, which is why the API's
 * production resolver requires a shared secret and refuses to start without one. Nothing
 * here changes that: the accounts below let a person choose which identity the
 * development resolver asserts, in place of editing environment variables and restarting
 * the server, and every one of them is gated on `NODE_ENV === "development"`.
 *
 * The passwords are the account names. That is deliberate and it is the point: a
 * credential that could plausibly be used in production would eventually be used in
 * production. These cannot be.
 *
 * What is *not* a demo shortcut is what each account can reach. `admin` sees other
 * organizations because the database says it is a `platform_admin` with a live support
 * access grant, checked by row-level security exactly as it would be for real platform
 * staff. Signing in as `admin` does not bypass a single policy; it asserts an identity
 * that the grants happen to cover.
 */

export type DevAccount = {
  username: string;
  password: string;
  subject: string;
  email: string;
  name: string;
  /** Shown on the sign-in page so it is obvious what each account is for. */
  descriptionKey: "signIn.adminDescription" | "signIn.expertDescription";
};

export const DEV_ACCOUNTS: readonly DevAccount[] = [
  {
    username: "admin",
    password: "admin",
    subject: "platform-admin",
    email: "admin@siembiot.local.test",
    name: "Mihai Constantin",
    descriptionKey: "signIn.adminDescription",
  },
  {
    username: "expert",
    password: "expert",
    subject: "demo-primar",
    email: "primar@primaria-exemplu.test",
    name: "Elena Marinescu",
    descriptionKey: "signIn.expertDescription",
  },
];

export const DEV_IDENTITY_COOKIE = "siembiot-dev-identity";

/**
 * Where a person goes once an identity is chosen.
 *
 * One constant rather than a string in each place that navigates. The sign-in page sends
 * you here, and the landing page sends you here when you are already signed in; if those
 * two disagreed, signing in and then reopening the app would land you somewhere else.
 */
export const SIGNED_IN_HOME = "/onboarding";

export function accountFor(username: string, password: string): DevAccount | null {
  const account = DEV_ACCOUNTS.find((candidate) => candidate.username === username);
  // Not constant-time, and it does not need to be: both credentials are in this file and
  // in the repository. Pretending otherwise would suggest the check protects something.
  return account && account.password === password ? account : null;
}

export function accountBySubject(subject: string): DevAccount | null {
  return DEV_ACCOUNTS.find((candidate) => candidate.subject === subject) ?? null;
}

export function developmentSignInEnabled(): boolean {
  return process.env.NODE_ENV === "development";
}

/**
 * Forget the chosen identity, from the browser.
 *
 * Needed because the landing page sends anybody holding this cookie straight into the
 * application: without a way to drop it, whichever account you picked first would be the
 * only one you could ever use, and the point of having two is comparing what each sees.
 *
 * `max-age=0` on the same path the cookie was set with. A mismatched path leaves the
 * original in place and the browser simply carries on sending it, which looks exactly
 * like the button doing nothing.
 */
export function signOutDevIdentity(): void {
  document.cookie = `${DEV_IDENTITY_COOKIE}=; path=/; max-age=0; samesite=lax`;
}

/** The identity currently chosen, read back from the cookie. */
export function currentDevAccount(cookieHeader: string): DevAccount | null {
  const match = new RegExp(`(?:^|;\\s*)${DEV_IDENTITY_COOKIE}=([^;]*)`).exec(cookieHeader);
  return match ? accountBySubject(decodeURIComponent(match[1])) : null;
}
