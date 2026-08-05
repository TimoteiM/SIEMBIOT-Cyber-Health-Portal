# Milestone 3 — Provider framework and deterministic collectors

**Status:** implemented. Verified on 2026-08-05.

**Goal:** ship the adapter contract and the keyless collectors that produce every core
piece of external evidence, with no paid provider key and no connection to a real
third party in any test.

## What was built

### Collection network boundary

Milestone 2 shipped a boundary shaped around one operation: fetching an ownership
verification file. Collection needs DNS queries, TLS handshakes, and HTTP requests at
several paths, so the boundary was generalized without loosening it.

| Module | Responsibility |
| --- | --- |
| `network_safety/host_policy.py` | Canonical host and DNS-name validation shared by every destination type |
| `network_safety/collection_policy.py` | `OperationClass` and per-class destination/path/redirect policy |
| `network_safety/dns_client.py` | Record-type allowlist, per-run query budget, record count/size caps |
| `network_safety/tls_client.py` | Handshake-only observation and bounded protocol probing |
| `network_safety/collection_broker.py` | The single gate: resolve → authorize → pin → connect → re-authorize |

Properties preserved from Milestone 2 and now covered for collection too:

- a destination is derived from an operation class, never from a provider response,
  a redirect body, or agent output;
- resolution happens immediately before each connection and every answer is
  authorized, so a redirect to a rebound address is refused;
- a fixed-path operation class (verification, MTA-STS) cannot be redirected to any
  other path;
- the tenant policy is re-read at every checkpoint, so a revocation mid-fetch stops it.

`OperationClass.DNS_QUERY` is bounded by allowlist rather than address policy, because
DNS resolution targets the configured recursive resolver, not the assessed host. Zone
transfers (`AXFR`/`IXFR`) and `ANY` are rejected by the allowlist.

### Adapter framework

`AdapterDescriptor` makes the contract from the brief mandatory at construction time:
capabilities, terms notes, data classification, required secrets, timeout, rate limit,
cost unit, cache policy, and fixture support. Contradictions are rejected — a free
adapter may not require a secret, a paid adapter must, a cache may not be enabled where
terms forbid storage, and every adapter must support fixtures.

`CollectionStatus` has no boolean pass/fail. `unavailable`, `not_applicable`, `denied`,
and `error` are distinct, and `partial` must enumerate what is missing.

`resilience.py` provides a token-bucket rate limiter, a three-state circuit breaker, a
quota ledger that treats its limit as a ceiling, a TTL cache that marks served entries
`from_cache`, and `summarize_claims`, which keeps disagreeing providers visible instead
of collapsing them into a single verdict.

### Collectors

| Collector | Pillar | Covers |
| --- | --- | --- |
| `dns_records` | A | Delegation, DNSSEC state, CAA, addresses, IPv6 presence, wildcard probe |
| `email_records` | B | MX, SPF, DMARC, declared-selector DKIM, MTA-STS, TLS-RPT, DANE, BIMI |
| `tls_certificate` | C | Chain, expiry, key/signature properties, hostname coverage, protocol posture |
| `http_surface` | C | HTTP→HTTPS redirect, security headers, cookies, disclosure headers |
| `rdap` | A | Registration and expiry events, registry status |
| `ct_log` | D | Asset candidates with attribution confidence |

Deliberate restraints:

- DKIM selectors come only from the organization's declaration; the list is capped and
  no wordlist is ever tried.
- BIMI is collected as informational and is not a security control.
- RDAP entity/contact objects are discarded; only registration facts are kept.
- CT names are candidates with a confidence and an attribution basis. A name that is
  not the authorized domain or a subdomain of it gets low confidence and an
  `unrelated_name` basis — discovery never implies ownership.
- Collectors parse and describe. No collector assigns a severity or a score.

## Verification

| Command | Result |
| --- | --- |
| `make test-network-safety` | 118 passed |
| `make test-adapters` | 62 passed |
| `make test-collectors` | 73 passed |
| `make providers-check` | matrix up to date |
| `uv run mypy` (strict, incl. `services/worker/src`) | no issues in 64 files |
| `uv run ruff check` / `ruff format --check` | clean |
| `uv run pytest` (non-database) | 303 passed |

The database-backed suites (`tests/database`, `tests/api`, two `tests/security`
modules) were **not** run in this session: they start PostgreSQL through Docker
Compose and no Docker daemon is available on this machine. They are unmodified by this
milestone except through the `TransportResponse.raw_headers` and `RequestDestination`
changes, which are exercised by the non-database network suite.

## Notes and limitations

- `cryptography==50.0.0` is now an explicit dependency (it was already present
  transitively through `pyjwt[crypto]`), used for X.509 parsing.
- The backend refuses to produce SHA-1 signatures, so the weak-signature
  classification is asserted directly rather than through a generated certificate.
- `make fixture-stack` runs the in-process fixture suites; collection fixtures need no
  container stack, so the target verifies the corpus rather than starting one.
- Passive asset intelligence and reputation adapters are catalogued with their terms
  and secrets declared, but no provider implementation ships yet — they report
  `unconfigured`. Wiring them is Milestone 5/9 work.
- Collectors are not yet driven by a workflow; orchestration is Milestone 5.
