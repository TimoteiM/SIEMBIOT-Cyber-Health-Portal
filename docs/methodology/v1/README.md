# SIEMBIOT Methodology 1.0

Methodology 1.0 is a deterministic, policy-as-data implementation for fictional fixture evidence. It is not a certification, legal-compliance determination, security guarantee, or live assessment capability.

Every evaluation and snapshot pins the policy content hash, methodology version, scoring behavior version, canonicalization version, evidence identities, and fixture/live mode. Historical snapshots are immutable. Recalculation under another version creates a new projection.

Run `make policy-validate test-normalization test-scoring methodology-reproduce` (or the documented command bodies on Windows) to validate the catalog and reproduce the fixture snapshot.
