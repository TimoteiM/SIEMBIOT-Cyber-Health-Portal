# ADR-0003: Authentication and Multi-tenancy

**Status:** Accepted — 2026-08-03

## Decision

Use standards-based OIDC. Ship Keycloak for local/community deployments and support compatible managed providers. The Next.js BFF exchanges OIDC state for an opaque server-side session; browsers receive `Secure`, `HttpOnly`, `SameSite` cookies, never local-storage tokens. State changes require CSRF and strict origin checks.

Keep organization membership/roles in SIEMBIOT. Enforce deny-by-default action and object authorization in the API, then PostgreSQL RLS as defense in depth. Platform support access is explicit, time-limited, reasoned, and audited. Platform administrators require phishing-resistant MFA/passkey assurance from the IdP.

## Consequences

Authentication is not custom cryptography, while tenant semantics remain product-owned. OIDC assurance/claim mappings need conformance tests and fail closed.
