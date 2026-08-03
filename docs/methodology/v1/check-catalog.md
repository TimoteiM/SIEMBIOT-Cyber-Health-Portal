# Check catalog 1.0

The machine-readable source is `packages/policy/checks/v1/`. Stable check IDs are never repurposed. The initial fixture catalog covers DNSSEC, DMARC, HSTS, CT attribution review, explicit provider-unavailable reputation state, and RDAP registration freshness across the six methodology pillars.

The validator rejects duplicate IDs, unsupported schemas, dangling references, missing remediation, non-positive weights, inconsistent pillar totals, and invalid cap definitions. Unsupported or unavailable evidence is reported as unknown; it is never inferred as pass or fail.
