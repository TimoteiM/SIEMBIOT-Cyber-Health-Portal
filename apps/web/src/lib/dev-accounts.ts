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
