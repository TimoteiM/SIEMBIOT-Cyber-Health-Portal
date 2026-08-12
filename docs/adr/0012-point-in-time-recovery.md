# ADR-0012: Point-in-time recovery for the audit trail

**Status:** Accepted — 2026-08-12

## Context

Backups are taken and verified; a restore has been executed against a real database and
checks schema, row counts, forced row-level security, append-only triggers, roles and the
audit chain. What a dump-only restore cannot do is recover anything written since the dump
was taken. The daily schedule therefore puts up to twenty-four hours of writes at risk.

The question this ADR settles is whether that is acceptable, and it does not have one
answer for the whole database. The two things this platform stores have opposite
properties, and treating them the same is how the decision gets made by accident.

**Evidence tolerates it.** Observations are reproducible: the same domain re-assessed
produces the same evidence, because that is what determinism was for. Evidence also
expires at ninety days under retention, so it is not a permanent record anybody relies on.
Losing a day of it costs a re-run.

**The audit trail does not.** It is the record of who did what — which support grant was
used, which domain was authorized, which organization was erased. It cannot be
reconstructed by re-running anything, because it is a record of decisions rather than of
observations.

And there is an asymmetry that decides the matter. **The event most likely to cause a
restore is the event whose audit record matters most.** A compromise, a mistaken erasure,
a dispute about whether an assessment was authorized — in each case the last hours before
the restore are precisely the hours somebody needs to see, and precisely the hours a
dump-only restore discards.

One thing that is *not* a consideration: chain integrity. The audit chain is per
organization and ordered, so a restore to an earlier point leaves a valid prefix.
`audit_chain_breaks()` returns nothing on a restored database. The loss is completeness,
not verifiability — which is worth stating because "the chain would break" would be a
reason to act, and it is not the reason.

## Decision

**Continuous archiving is required, and it is required for the audit trail.**

PostgreSQL write-ahead log archiving to the same off-host destination as the base backups,
retained for at least as long as the base backup it belongs to. Recovery is base backup
plus replay to a chosen time.

This is a decision about the database as a whole, because WAL archiving cannot be scoped
to one table. Evidence gets point-in-time recovery it does not need as a side effect of
the audit trail getting the recovery it does. That is an acceptable cost — the alternative
is separating the audit trail into its own database, which would put the accountability
record outside the transaction that produced it and make "the action happened but the
record did not" representable.

**Recovery point objective: five minutes.** Not zero. Zero requires synchronous
replication to a second host, which is a different topology with a latency cost on every
write, and is not warranted by a free platform serving public institutions.

## Consequences

Archiving must be configured before this is true of a deployment: `archive_mode`, an
`archive_command` writing to the backup destination, and a `restore_command` for recovery.
`SIEMBIOT_BACKUP_DESTINATION` already refuses a destination that shares a filesystem with
the data directory, and archives inherit that refusal.

**This ADR is a decision, not an implementation.** The archiving configuration and the
destination it writes to are deployment infrastructure with credentials attached, and this
repository does not have them. `docs/operations/deployment.md` records point-in-time
recovery as configured-by-the-deployment rather than as done, and will keep saying so
until a deployment demonstrates a recovery to a chosen time the way the restore drill
demonstrates a base restore.

Until then the honest statement is the one that is written down: a restore loses up to a
day, and the audit trail is the part of that which cannot be reconstructed.
