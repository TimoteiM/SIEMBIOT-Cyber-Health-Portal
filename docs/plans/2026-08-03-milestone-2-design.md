# Milestone 2 Domain Authorization and Network Safety Design

**Status:** Approved by the Milestone 2 product and security decisions on 2026-08-03

## Outcome

Milestone 2 introduces a private, tenant-isolated lifecycle that moves a domain through three deliberately separate facts: the domain was added, control was verified, and a named actor explicitly authorized a bounded operation. Only an active signed scope manifest may authorize a target network operation. Verification, authorization, and emergency-control changes are independently revocable and auditable.

No collectors, asset discovery, scoring, public scanning, Tyche orchestration, arbitrary URL fetch, browser automation, port scanning, or shell execution is introduced.

## Approaches considered

1. **Narrow in-process policy and broker boundary (selected).** The API owns business state and invokes a separately packaged network-safety broker through typed interfaces. The broker accepts a structured verification request, not a URL, and injects resolver, transport, clock, limit, and authorization dependencies. This provides one enforceable boundary now and can move behind the durable worker interface later without changing contracts.
2. **Dedicated egress microservice now.** This gives stronger process isolation but would introduce service identity, deployment, and queue semantics before their approved milestones. It is deferred; production network policy remains a later defense-in-depth requirement.
3. **Direct HTTP/DNS calls in domain handlers.** This is rejected because it duplicates authorization, enables SSRF bypasses, and cannot reliably pin resolved addresses or revalidate redirects.

## Domain identity

One normalization function accepts only a domain string. It rejects URLs, IP literals, ports, paths, credentials, wildcards, whitespace ambiguity, malformed IDNs, empty labels, overlong names/labels, public suffixes, and trailing dots. It stores a lowercase ASCII A-label canonical name and a normalized Unicode display form. UTS #46 non-transitional processing with STD3 rules is used through the pinned `idna` dependency.

Registrable-domain and public-suffix decisions use a vendored Public Suffix List snapshot pinned to upstream commit `e1b8015c3b2f0f4f8c18659c2480fc1a22c07b20`. The snapshot has recorded provenance and digest and is never updated at runtime. Wildcard and exception rules are tested. Punycode and mixed Latin/Cyrillic/Greek scripts create neutral warnings; they never assert malicious intent.

A verified registrable domain does not silently verify or authorize a separately delegated child zone. Each stored domain is an exact canonical target. Parent/child relationships may be shown, but authorization target matching is exact unless the immutable manifest explicitly lists each host.

## Verification state machine

Domain ownership state is `pending`, `verified`, `expired`, `failed`, `revoked`, or `reverification_required`. Challenges are single-purpose, cryptographically random, short-lived, and stored only as SHA-256 digests. At most one active challenge exists per domain and method. Creation and verification use database-backed time windows and attempt counters, with row locking for concurrency.

DNS TXT verification queries `_tyche-verify.<canonical-domain>`. HTTPS verification requests only `https://<canonical-domain>/.well-known/tyche-verification.txt`; an HTTP-to-HTTPS redirect is allowed only after complete destination reauthorization. Administrative-email verification is deferred.

Challenge plaintext appears once in the creation response and is excluded from audit context, logs, database rows, and later reads. Verification compares digests in constant time. Success records when reverification is due. Expiry, excessive attempts, revocation, or delegation/material DNS change fail closed.

## Authorization and signed manifests

Authorization is a distinct state machine: `draft`, `active`, `expired`, or `revoked`. Acceptance records the organization, actor, exact domain/host targets, allowed operation classes, policy version, consent version/text digest, validity interval, and revocation metadata.

Activation produces canonical JSON using sorted UTF-8 keys, no insignificant whitespace, UTC timestamps, and versioned field names. The exact bytes are hashed with SHA-256 and signed through a `ManifestSigner` interface. Milestone 2 uses Ed25519 (`EdDSA`) with a key ID. Development may generate or load a clearly tagged development-only key; production configuration rejects development keys and missing external key configuration. Verification accepts an explicit active-key set to support rotation and rejects unknown key IDs, altered bytes, invalid signatures, expired/revoked authorization, inactive verification, or suspended scope.

Every broker call carries the manifest identifier and exact target. Authorization is checked before resolution, after resolution, before connect, on every redirect, and during bounded response reads. Revocation therefore invalidates future operations immediately and interrupts cooperative in-flight work at the next checkpoint.

## Central network-safety broker

The broker exposes purpose-specific operations such as `fetch_https_verification`; it never exposes a generic fetch API. It builds the only permitted verification destination itself. It ignores proxy environment variables and never accepts userinfo, fragments, arbitrary paths, unsupported schemes, noncanonical hosts, or ports outside the operation policy.

The controlled resolver runs immediately before each connection and returns all A/AAAA answers. Every answer is canonicalized with `ipaddress`; nonstandard integer, hexadecimal, octal, shortened, zone-scoped, and IPv4-mapped bypass forms are rejected. Loopback, private, link-local, multicast, unspecified, reserved, benchmarking, documentation, carrier-grade NAT, metadata, and policy-maintained special ranges are blocked. A mixed public/forbidden set blocks the entire decision.

The transport connects only to a validated resolved address while preserving the authorized Host header and TLS SNI. Redirects are limited, normalized, re-resolved, and reauthorized; cross-domain redirects are denied unless the manifest lists the exact target. Deadlines, header/body byte ceilings, read chunk limits, redirect counts, per-tenant/domain concurrency, and verification-attempt limits are explicit typed budgets. No DNS or authorization decision is cached in Milestone 2.

Blocked decisions return safe reason codes and audit only canonical target metadata, address classification counts, manifest ID, and policy version. Response bodies, challenge plaintext, credentials, and detailed internal errors are never audited.

## Emergency controls

Fail-closed controls may target global, organization, domain, or operation class scope. Each control records reason, actor, creation time, optional expiry, and deactivation metadata. Global activation requires a platform administrator with phishing-resistant MFA; organization/domain/operation activation requires an organization owner or security administrator. Support grants never bypass controls or target authorization.

The policy decision reads authoritative state at every broker checkpoint. Activation blocks new operations and causes queued or cooperative in-flight operations to transition to rejected/cancelled. Recovery is explicit: inspect status, verify the reason is resolved, deactivate with a new audit event, then create new work; old revoked manifests or challenges are never resurrected.

## Storage and trust boundaries

PostgreSQL remains authoritative. Domain, challenge, verification-event, authorization, manifest, target, emergency-control, and network-operation tables carry organization identity where applicable, use forced RLS, and have object constraints. Immutable manifests and verification/audit events deny update/delete to the application role and have defensive triggers. Private verification and authorization rows are absent from public schemas and routes.

The API applies deny-by-default RBAC and object authorization before database operations. PostgreSQL independently enforces tenant scope. Network policy is a third decision boundary and does not infer authorization from reachability or domain verification alone.

## UI and errors

The Romanian-first flow shows `Domeniu adăugat → Proprietate verificată → Testare autorizată` as separate backend-confirmed states. It presents DNS/HTTPS instructions, expiry, remaining attempts, propagation guidance, scope, consent version, manifest status, revocation, and emergency suspension. Accessible live regions and focusable error summaries cover loading, expiry, permission denial, DNS propagation, blocked destination, cancellation, and partial failure. The client never computes an authorization success state.

## Verification strategy

Tests are written first for each boundary. Unit/property tests cover normalization, IDN/PSL behavior, canonical JSON, signatures, key rotation, IP/URL parsing, budgets, redirect policy, and reason-code redaction. PostgreSQL tests cover migration from empty, constraints, partial uniqueness, RLS, immutability, revocation, and emergency controls. API tests cover state transitions, RBAC, IDOR, rate limits, and sensitive-data omission. Broker tests use deterministic fake DNS/transport fixtures and prove no external connection occurs. Web tests assert backend-driven state and absence of client-side authorization bypass.

Acceptance requires the complete repository verifier, focused domain/network/RLS suites, contract drift, migration downgrade/re-upgrade in disposable development storage, and a production web build to pass.
