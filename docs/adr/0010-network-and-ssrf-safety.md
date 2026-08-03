# ADR-0010: Centralized Network and SSRF Safety

**Status:** Accepted — 2026-08-03

## Decision

All target/provider network access passes through one reusable egress policy library and restricted collector network path. It accepts structured host/port/protocol inputs, never arbitrary user URLs. It normalizes IDNs, verifies scope/consent/profile, resolves A/AAAA immediately before connecting, rejects non-global/private/loopback/link-local/multicast/reserved/metadata ranges, pins the permitted address for the connection, and revalidates every redirect and new DNS resolution.

Active checks additionally require current domain verification, signed scope manifest, explicit authorization, allowlisted ports/methods, low concurrency, deadlines, byte limits, audit, organization suspension state, and global kill switch. DNS answers and changes are recorded. Network policy blocks all other egress.

## Consequences

Collectors must use the central client; direct sockets/HTTP clients fail static/architecture tests. IPv4/IPv6 encoding, redirect, rebinding, proxy, and parser bypasses require adversarial tests.
