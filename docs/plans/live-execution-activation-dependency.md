# Live Execution Activation Dependency

**Status:** Mandatory future dependency; not implemented or approved for activation

Milestone 3 validates collector behavior only through deterministic local fixtures. No configuration value, environment variable, feature flag, tenant role, or support grant may enable live target/provider execution.

Live execution remains blocked until one later reviewed milestone delivers and verifies all eight controls together:

1. a separately deployed restricted-egress broker service;
2. isolated collector workers and deny-by-default outbound network policy;
3. authoritative tenant, manifest, target, operation, revocation, and emergency-control reauthorization immediately before every connection;
4. controlled DNS resolution, complete-address validation, address pinning, and redirect re-resolution/reauthorization;
5. provider credentials isolated to the smallest adapter workload and never exposed to collectors, logs, models, or tenants;
6. enforced rate, cost, retry, time, response-size, concurrency, circuit-breaker, cancellation, and kill-switch budgets;
7. production-like deployment, SSRF/rebinding/redirect, isolation, secret, cancellation, failover, and security tests;
8. an explicit recorded product/security approval that changes execution policy from fixture-only to a specifically allowlisted live profile.

The dependency is conjunctive: partial delivery does not permit live execution. Milestone 5 may introduce durable isolated worker and broker contracts; Milestone 10 must prove deployment and network-policy enforcement. Activation cannot occur before both are accepted and the explicit approval in item 8 is recorded.
