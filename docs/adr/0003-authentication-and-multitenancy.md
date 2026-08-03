# ADR-0003: Authentication and Multi-tenancy

**Status:** Accepted — 2026-08-03

## Decision

Use standards-based OIDC. Ship Keycloak for local/community deployments and support compatible managed providers. The same-origin web/BFF boundary routes authentication to the FastAPI auth module, which performs discovery, state/nonce/PKCE validation, code exchange, and signed ID-token validation before creating an opaque server-side session. Browsers receive `Secure`, `HttpOnly`, `SameSite` cookies, never local-storage tokens. State changes require an in-memory CSRF value and exact origin checks.

Keep organization membership/roles in SIEMBIOT. Enforce deny-by-default action and object authorization in the API, then PostgreSQL RLS as defense in depth. Platform support access is explicit, time-limited, reasoned, and audited. Platform administrators require phishing-resistant MFA/passkey assurance from the IdP.

## Consequences

Authentication is not custom cryptography, while tenant semantics remain product-owned. OIDC assurance/claim mappings need conformance tests and fail closed.

## Milestone 1 implementation evidence

Provider configuration is issuer/client based and tenant/role claims are ignored. Session and OIDC transaction secrets are hashed or encrypted at rest, state is one-time, and expired/revoked sessions fail closed. The role/action matrix, object lookup, forged-tenant, cross-tenant, revoked-membership, role-escalation, support-grant, CSRF, and unauthenticated cases are covered by the security and PostgreSQL integration suites.
