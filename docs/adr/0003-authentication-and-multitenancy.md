# ADR-0003: Authentication and Multi-tenancy

**Status:** Accepted — 2026-08-03

## Decision

Use standards-based OIDC. Ship Keycloak for local/community deployments and support compatible managed providers. The same-origin web/BFF boundary routes authentication to the FastAPI auth module, which performs discovery, state/nonce/PKCE validation, code exchange, and signed ID-token validation before creating an opaque server-side session. Browsers receive `Secure`, `HttpOnly`, `SameSite` cookies, never local-storage tokens. State changes require an in-memory CSRF value and exact origin checks.

Keep organization membership/roles in SIEMBIOT. Enforce deny-by-default action and object authorization in the API, then PostgreSQL RLS as defense in depth. Platform support access is explicit, time-limited, reasoned, and audited. Platform administrators require phishing-resistant MFA/passkey assurance from the IdP.

## Consequences

Authentication is not custom cryptography, while tenant semantics remain product-owned. OIDC assurance/claim mappings need conformance tests and fail closed.

## Milestone 1 implementation evidence

Provider configuration is issuer/client based and tenant/role claims are ignored. Session and OIDC transaction secrets are hashed or encrypted at rest, state is one-time, and expired/revoked sessions fail closed. The role/action matrix, object lookup, forged-tenant, cross-tenant, revoked-membership, role-escalation, support-grant, CSRF, and unauthenticated cases are covered by the security and PostgreSQL integration suites.

## Correction — 2026-08-12: the audit trail was weaker than this ADR implied

Two properties this decision depends on were not true in the shipped product, from
migration `0001` until 2026-08-12. Recorded here rather than only in the changelog,
because a future incident review will start from the ADR that claims audit as a control.

**The trail was append-only but not tamper-evident.** `audit_events` carried
`previous_hash` and `event_hash` with a CHECK constraint fixing them at 32 bytes, and
nothing ever wrote either. Append-only stops the application rewriting history; a chain is
what stops whoever holds the database credentials, which is the case an audit trail exists
for. Migration `0019` chains events per organisation in a trigger, so the chain covers
writes that never went through the application. Pre-existing rows are not backfilled: they
are reported as predating tamper-evidence, because hashing them now would certify whatever
they currently say and launder an already-altered row as genuine.

**Denied attempts were never recorded.** `authorize` appended `authorization.denied` and
then raised, both inside the request's transaction, and the rollback discarded the write.
"Platform support access is explicit, time-limited, reasoned, and audited" was true of
granted access and false of refused access — and refusals are the entries an investigation
wants most. Fixed by writing the refusal on its own connection.

Both failed silently and looked correct: one as a schema with hash columns, the other as
code that plainly called `append_audit_event`. Anything relying on audit history from
before 2026-08-12 should be read with both limitations in mind.
