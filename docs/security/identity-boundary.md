# Identity boundary

**Authentication is not implemented in this service.** It is owned by a separate team
and terminates upstream. This document defines the contract between that layer and this
one.

## What was removed and what was kept

Removed: the OIDC authorization-code flow, PKCE handling, server-side sessions, session
cookies, CSRF token issuance, the login/callback/logout endpoints, and the local
Keycloak container.

**Kept, deliberately:** tenant isolation, role-based access control, object-level
authorization, PostgreSQL row-level security, audit actor attribution, support-access
grants, and strict origin checking on state changes.

Authentication and authorization are different things. Removing the former does not
remove the latter — "no cross-tenant data exposure" remains a release-blocking
invariant, and every one of those controls is still exercised by the test suite.

## The contract

The upstream layer authenticates the caller and forwards the result as headers:

| Header | Required | Meaning |
| --- | --- | --- |
| `X-SIEMBIOT-Identity-Issuer` | yes | Stable identifier of the identity provider |
| `X-SIEMBIOT-Identity-Subject` | yes | Stable, opaque subject identifier within that issuer |
| `X-SIEMBIOT-Identity-Email` | yes | Verified e-mail address |
| `X-SIEMBIOT-Identity-Name` | no | Display name; falls back to the e-mail address |
| `X-SIEMBIOT-Gateway-Secret` | yes | Shared secret proving the request came from the gateway |

`(issuer, subject)` is the join key to a local user. It must be **stable for the
lifetime of the person's account** and must never be reused for a different person. An
e-mail change updates the existing user; it does not create a second one.

The identity is provisioned just in time: the first request from an unseen
`(issuer, subject)` creates the local user row. Membership of an organization is a
separate, explicit act — a newly provisioned user can see nothing until invited.

## Why the shared secret

Without it, anyone who can reach this service directly could set the identity headers
and become any user. The secret proves the request passed through the gateway.

It is therefore **mandatory that this service is not directly reachable** from
untrusted networks. The secret is defence in depth, not a substitute for network
placement. Configure it through `SIEMBIOT_IDENTITY_GATEWAY_SECRET`; it must be at
least 32 characters and rotated like any other credential.

## Fail-closed behaviour

| Situation | Result |
| --- | --- |
| No identity headers | `401 unauthenticated` |
| Headers present, no gateway secret | `401 unauthenticated` |
| Headers present, wrong gateway secret | `401 unauthenticated` |
| Malformed or oversized header values | `401 unauthenticated` |
| State change without a matching `Origin` | `403 origin_rejected` |
| Non-development environment with no gateway secret configured | **the service refuses to start** |

That last row matters most: the development resolver trusts the headers with no secret,
so it would be an authentication bypass if it ever ran in a deployed environment.
`build_identity_resolver` raises rather than falling back to it.

## Local development

A browser cannot set request headers on its own, so with no gateway in front of the
app every page would sit at `401`. Two pieces close that gap locally.

**The API** uses the development resolver, which reads the identity headers directly
when the environment is `development` and no gateway secret is configured.

**The web application** injects those headers in `apps/web/src/middleware.ts`. It is
gated three ways and all three must hold: `NODE_ENV` is exactly `development`,
`SIEMBIOT_DEV_IDENTITY_SUBJECT` is explicitly set, and an identity already present on
the request is never overwritten. It injects no gateway proof, so the production
resolver would reject the headers anyway — the convenience cannot survive a real
deployment even if the code path were somehow reached.

Set the identity in `.env`:

```
SIEMBIOT_DEV_IDENTITY_ISSUER=https://idp.local.test
SIEMBIOT_DEV_IDENTITY_SUBJECT=local-analyst
SIEMBIOT_DEV_IDENTITY_EMAIL=analist@example.test
SIEMBIOT_DEV_IDENTITY_NAME="Ana Popescu"
```

Leaving `SIEMBIOT_DEV_IDENTITY_SUBJECT` empty disables injection entirely, which is
how you exercise the unauthenticated states. To call the API directly, send the
headers yourself:

```bash
curl http://127.0.0.1:8000/api/v1/session \
  -H 'X-SIEMBIOT-Identity-Issuer: https://idp.local.test' \
  -H 'X-SIEMBIOT-Identity-Subject: local-analyst' \
  -H 'X-SIEMBIOT-Identity-Email: analist@example.test' \
  -H 'X-SIEMBIOT-Identity-Name: Ana Popescu'
```

## What the other team still needs to provide

1. A gateway or proxy that authenticates the user and injects the headers above.
2. Session lifetime, revocation, and logout — none of which this service tracks any more.
3. **CSRF defence for browser state changes.** This service still enforces a strict
   origin check, but token-based CSRF belongs to whoever issues the session cookie.
   If the gateway authenticates browsers with a cookie, it must handle CSRF.
4. Phishing-resistant MFA for platform administrators. The database still records the
   assurance requirement (`platform_role`, support-access grants), but this service no
   longer observes how the user authenticated, so it cannot enforce it alone.

Items 3 and 4 are **open security gaps** created by this split. They are tracked here
rather than silently dropped, and must be closed before any production launch.
