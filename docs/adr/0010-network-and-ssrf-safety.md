# ADR-0010: Centralized Network and SSRF Safety

**Status:** Accepted — 2026-08-03

## Decision

All target/provider network access passes through one reusable egress policy library and restricted collector network path. Callers receive purpose-specific operations, never arbitrary URL/method/port access. The implemented ownership-verification operation accepts only a canonical host and a fixed HTTPS well-known path. It resolves every A/AAAA answer immediately before connecting, rejects non-global/private/loopback/link-local/multicast/reserved/metadata ranges, fails closed on mixed answers, pins one address from the validated set while preserving Host/SNI, and revalidates every redirect and new DNS resolution.

Ownership verification is the prerequisite for, not evidence of, assessment authorization. It therefore requires a current digest-only challenge and current emergency-control policy but no assessment manifest. Later passive or active assessment I/O must additionally require current verification, explicit consent, a valid signed scope manifest, and an exact manifest target. The broker enforces concurrency, connect/read/total deadlines, header/body/redirect limits, and policy checks before resolution, after resolution, before connect, after headers, during body reads, and before redirects. Decision records contain reason codes and counts, never resolved addresses, challenge values, or bodies. Network policy blocks all other egress.

## Consequences

The current in-process typed broker is the only permitted network boundary for HTTPS ownership verification. Moving it behind a separately deployed restricted-egress service remains part of the durable worker/collector milestone and does not change its contracts. Direct sockets/HTTP clients outside this module fail architecture tests. IPv4/IPv6 encoding, redirect, rebinding, proxy, response-framing, budget, and parser bypasses require adversarial tests.
