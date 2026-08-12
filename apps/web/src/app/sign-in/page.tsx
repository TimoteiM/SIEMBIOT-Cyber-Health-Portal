"use client";

import { FormEvent, useState } from "react";

import { useLocalization } from "../../lib/i18n/provider";
import type { MessageKey } from "../../lib/i18n";
import {
  accountFor,
  DEV_ACCOUNTS,
  DEV_IDENTITY_COOKIE,
  developmentSignInEnabled,
  SIGNED_IN_HOME,
} from "../../lib/dev-accounts";

/**
 * Choosing which identity to work as, locally.
 *
 * Deliberately not called "log in" anywhere a reader can see it: nothing is
 * authenticated here. Real deployments terminate identity at a gateway upstream, and the
 * API's production resolver refuses to start without the shared secret that proves the
 * gateway is the caller. This page exists because a laptop has no gateway, and editing
 * environment variables to change persona meant restarting the server every time.
 *
 * The page says all of that on itself, because a sign-in form that does not authenticate
 * is exactly the kind of thing somebody later mistakes for one.
 *
 * **In a production build it renders no form at all.** The root redirects here in every
 * build -- the first page a person meets is the sign-in page -- so what arrives in a real
 * deployment has to be true there. A form that sets a cookie the middleware will not read,
 * leading to a page that answers 401, is a dead end shaped like a login; saying instead
 * that identity was established upstream is both shorter and correct.
 */
export default function SignInPage() {
  const { t } = useLocalization();
  const [message, setMessage] = useState<MessageKey | null>(null);

  function signIn(username: string, password: string) {
    const account = accountFor(username, password);
    if (!account) {
      setMessage("signIn.rejected");
      return;
    }
    // A session cookie, so closing the browser ends it. `SameSite=Lax` because the
    // value only selects between accounts defined in the repository.
    document.cookie = `${DEV_IDENTITY_COOKIE}=${account.subject}; path=/; samesite=lax`;
    // A full navigation rather than a client transition: the identity is injected by
    // middleware on the request, so the next request has to actually leave the browser.
    window.location.href = SIGNED_IN_HOME;
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    signIn(String(data.get("username") ?? ""), String(data.get("password") ?? ""));
  }

  // Statically replaced at build time, so the production bundle never takes the branch
  // below. The credentials it guards are in the repository anyway -- the point is not to
  // hide them, it is that a real deployment must not present a form it cannot honour.
  if (!developmentSignInEnabled()) {
    return (
      <section className="panel narrow" aria-labelledby="sign-in-title">
        <p className="eyebrow">{t("landing.eyebrow")}</p>
        <h1 id="sign-in-title">{t("landing.title")}</h1>
        <p>{t("landing.intro")}</p>
        <a className="button primary" href={SIGNED_IN_HOME}>
          {t("landing.enter")}
        </a>
        <p className="hint">{t("landing.note")}</p>
      </section>
    );
  }

  return (
    <section className="panel narrow" aria-labelledby="sign-in-title">
      <p className="eyebrow">{t("signIn.eyebrow")}</p>
      <h1 id="sign-in-title">{t("signIn.title")}</h1>

      {/* Said before the form, not after it. */}
      <div className="remediation-caveat" role="note">
        <p>{t("signIn.notRealAuthentication")}</p>
      </div>

      <form onSubmit={submit}>
        <label htmlFor="username">{t("signIn.username")}</label>
        <input id="username" name="username" required autoComplete="off" autoFocus />
        <label htmlFor="password">{t("signIn.password")}</label>
        <input id="password" name="password" type="password" required autoComplete="off" />
        <button className="button primary" type="submit">
          {t("signIn.submit")}
        </button>
      </form>

      <h2>{t("signIn.accountsHeading")}</h2>
      <ul className="card-list sign-in-accounts">
        {DEV_ACCOUNTS.map((account) => (
          <li key={account.username}>
            <div>
              <strong>{account.username}</strong>
              <p className="muted">{t(account.descriptionKey)}</p>
            </div>
            <button
              className="button secondary"
              type="button"
              onClick={() => signIn(account.username, account.password)}
            >
              {t("signIn.useAccount")}
            </button>
          </li>
        ))}
      </ul>

      <p className="status" role="status" aria-live="polite">
        {message ? t(message) : ""}
      </p>
    </section>
  );
}
