# Milestone 3 Provider and Collector Matrix

Milestone 3 is fixture-only. It validates normalization, failure handling, budgets, and broker enforcement against deterministic local data. It does not contact targets or providers and does not support live assessments.

| Capability | Adapter | Credentials | Milestone 3 mode | Live status | Output |
| --- | --- | --- | --- | --- | --- |
| DNS and DNSSEC | `fixture-internet` | none | fixture | unavailable | versioned observations |
| E-mail DNS | `fixture-internet` | none | fixture | unavailable | MX/SPF/DMARC/MTA-STS/TLS-RPT/TLSA/BIMI and declared DKIM selectors |
| HTTP metadata | `fixture-internet` | none | fixture | disabled by policy | bounded HEAD and allowlisted security.txt metadata |
| TLS metadata | `fixture-internet` | none | fixture | disabled by policy | version/cipher/chain/hostname/validity metadata |
| RDAP | `fixture-internet` | none | fixture | unavailable | normalized status/events and entity roles only |
| Certificate Transparency | `fixture-internet` | none | fixture | unavailable | passive name assertions; never asset authority |

Every adapter declares capability, terms note, classification, health semantics, timeout, rate and cost units, cache policy, fixture support, output schema, and retry policy. Fixture adapters are rejected if they declare a secret. Missing or failed data remains `unavailable`, `unknown`, or `error`; it never becomes a pass.

Provider disagreement is retained with adapter identity and confidence. No provider credential is read, accepted, or required in this milestone.
