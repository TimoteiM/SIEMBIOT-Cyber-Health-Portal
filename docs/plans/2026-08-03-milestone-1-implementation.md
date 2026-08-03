# Milestone 1 Implementation Plan

**Status:** approved requirements decomposed for implementation

**Goal:** deliver the typed contracts, PostgreSQL authority, provider-neutral OIDC BFF session lifecycle, organization and membership lifecycle, deny-by-default authorization, PostgreSQL RLS, and immutable audit trail required to make later private features safe.

## Consistency review

This plan was checked against the master product specification, target architecture, ADRs 0003 and 0004, the threat model, and the production implementation plan. It preserves these invariants:

- the browser receives only an opaque server-side session cookie; OIDC access, refresh, and session tokens are never placed in browser storage;
- organization context is selected by URL/object identifier but authorized from the current database membership, never trusted from a header or identity-provider tenant claim;
- every tenant-owned row is protected in the API authorization layer and PostgreSQL RLS;
- authorization is deny-by-default, role and action based, and object scoped;
- audit events are append-only and application database roles cannot update or delete them;
- platform administration confers no implicit tenant read access;
- Tyche, agents, collectors, scoring, providers, queues, and assessment workflows remain absent;
- the upstream credential exposure remains documented as an unresolved production launch blocker and is never accessed or imported.

## Task 1: Versioned contracts and API skeleton

1. Add failing contract tests for UUIDs, RFC 3339 UTC timestamps, pagination, the error envelope, sessions, organizations, memberships, invitations, and audit events.
2. Add versioned JSON Schemas and a checked-in OpenAPI document.
3. Add a typed FastAPI skeleton with correlation IDs, generic errors, private no-store responses, and schema drift verification.
4. Generate and type-check the shared TypeScript API definitions.
5. Commit only after contract, lint, type, and repository gates pass.

## Task 2: PostgreSQL authority and migrations

1. Add reproducible PostgreSQL Compose startup using distinct migration-owner and least-privilege application roles.
2. Add migration tests that fail before the schema exists.
3. Add Alembic migrations for users, organizations, memberships, invitations, OIDC login transactions, server-side sessions, support-access grants, and audit events.
4. Add foreign keys, uniqueness, state constraints, expiration/revocation metadata, tenant RLS, tenant-context functions, and audit immutability triggers/privileges.
5. Test empty upgrade, previous-revision upgrade, application-role RLS, forged context, cross-tenant object identifiers, revoked membership, audit update/delete denial, and development downgrade/re-upgrade.

## Task 3: OIDC and session lifecycle

1. Write failing tests for discovery-based login, PKCE/state/nonce callback validation, secure cookie attributes, session rotation, expiry, revocation, logout, CSRF/origin enforcement, and unauthenticated access.
2. Implement a provider-neutral OIDC adapter using issuer discovery and signed ID-token validation.
3. Persist one-time login state and hashed opaque session/CSRF secrets server-side.
4. Store provider tokens only server-side when required for logout; never return them to the browser or logs.
5. Add generic failure handling and security audit events.

## Task 4: Organizations, memberships, RBAC, and audit API

1. Write the role/action matrix and failing tests for organization creation, membership/invitation lifecycle, role escalation, object authorization, forged tenant identifiers, revoked membership, and explicit support grants.
2. Implement centralized principal, tenant-context, action, and object authorization dependencies.
3. Implement organization, member, invitation, current-session, and audit endpoints with typed responses.
4. Emit immutable structured audit events for every security-relevant success and denial without secrets.
5. Verify API decisions and RLS independently reject cross-tenant access.

## Task 5: Runnable Romanian-first web shell and documentation

1. Add a minimal accessible Next.js shell for login, onboarding, team, and audit states without browser token storage.
2. Add unit tests for secure client behavior and permission/error states.
3. Document local PostgreSQL/OIDC setup, migrations from empty, development rollback, test identities, and exact commands.
4. Update architecture, threat model, changelog, environment template, CI, and repository verifier.
5. Run bootstrap, contracts, API, web, database/RLS, security, migration, and full repository verification before the milestone commit.

## Milestone verification

The milestone is complete only when a clean database upgrades to head, the development rollback/re-upgrade test passes, application and RLS isolation tests pass, all negative authentication/authorization cases pass, the web and API remain runnable, generated contracts have no drift, the full repository verifier is green, `git diff --check` passes, and the implementation worktree is clean.
