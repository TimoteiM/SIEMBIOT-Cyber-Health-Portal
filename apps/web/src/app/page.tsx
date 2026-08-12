import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import {
  accountBySubject,
  DEV_IDENTITY_COOKIE,
  developmentSignInEnabled,
  SIGNED_IN_HOME,
} from "../lib/dev-accounts";

/**
 * The first page, which is the sign-in page.
 *
 * Opening the application and being shown a hero with a button is a step that exists
 * only to be clicked through. So the root redirects to `/sign-in` -- and straight past it
 * to the application when an identity has already been chosen, because bouncing a
 * signed-in person back to a sign-in page reads as the session having been lost.
 *
 * **This holds in a real deployment too, and what changes is the page it arrives at.**
 * A deployment terminates identity at a gateway upstream and has no credentials to
 * collect, so `/sign-in` there states that authentication happened before the request
 * reached this portal, and offers the way in. It does not render a form.
 *
 * That distinction is the whole of it. Sending somebody to a page that says on its face
 * that it does not authenticate would be worse than no redirect at all -- so the page
 * stops saying it, and stops showing a form nobody can submit, rather than the redirect
 * being withheld.
 */
export default async function LandingPage() {
  if (developmentSignInEnabled()) {
    const chosen = (await cookies()).get(DEV_IDENTITY_COOKIE)?.value;
    // Resolved against the accounts that exist rather than merely being present: a
    // cookie left over from a renamed account would otherwise send somebody into the
    // application with an identity the API will not accept, and the failure would
    // surface several pages later as an unexplained 401.
    redirect(chosen && accountBySubject(chosen) ? SIGNED_IN_HOME : "/sign-in");
  }

  // A deployment has no cookie to read: the gateway has already decided, and anybody
  // arriving here either was authenticated upstream or was never going to be.
  redirect("/sign-in");
}
