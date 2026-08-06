# Database roles

Three roles, and the distinction between them is load-bearing. Getting it wrong does
not produce an error — it produces a working system with no tenant isolation.

| Role | Used by | Bypasses RLS |
| --- | --- | --- |
| `siembiot_owner` | migrations only | **yes** — it is a superuser |
| `siembiot_app` | the API | no |
| `siembiot_worker` | the queue worker | no |

## Why this is written down

The API was running as `siembiot_owner`.

`Settings.database_url` read `SIEMBIOT_DATABASE_URL`, which is the owner's connection
string. The owner is created as the PostgreSQL superuser, and **superusers bypass
row-level security even where it is declared `FORCE ROW LEVEL SECURITY`**. Every policy
in the schema was correct, every policy was enabled and forced, and none of them
applied.

Nothing failed. No error was logged, no query was rejected, no test went red — the
tests pass the application role explicitly, so they exercised a code path the running
service did not use. It surfaced only because someone opened the assessments screen and
noticed it was offering to assess another organization's domain.

That is the shape of this class of bug: the failure mode of a privilege mistake is
silence. So it gets two defences, because either alone can be satisfied while the
service is still wrong.

**The variable that is read.** `Settings.app_database_url` maps to
`SIEMBIOT_APP_DATABASE_URL`. It is named for the role it carries rather than for "the
database", so that `SIEMBIOT_DATABASE_URL` reads as what it is: the migration
credential, and nothing else.

**The role that is connected.** `Database.verify_least_privilege()` runs at startup and
asks PostgreSQL, not the configuration, who we are:

```sql
SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user
```

If the answer is a superuser or a `BYPASSRLS` role, the service refuses to start. A
variable is a claim; `current_user` is the fact. Refusing to serve is the only outcome
that cannot be overlooked.

`tests/api/test_least_privilege.py` covers both halves, and additionally asserts that
**every** table carrying an `organization_id` has row-level security both enabled *and*
forced — so a table added later cannot join the schema without its isolation. Enabled
alone is not enough: without `FORCE`, the table's own owner still bypasses it.

## The worker's role

`siembiot_worker` exists because every policy written before it asked whether the
current *person* has an active membership — a question the worker cannot answer, since
it acts on nobody's behalf. Migration 0009 lets it write inside an organization without
a membership, but only the organization named in `app.organization_id`, so a worker
connection is confined to one tenant exactly as a user's is.

It is a separate login role rather than a session flag for one reason: whoever can talk
to the database as `siembiot_app` can already set any session variable they like. If
the worker's write permission were a flag, that would be enough to write into any
tenant. A role requires credentials the API does not have.

See [queue-boundary.md](../architecture/queue-boundary.md) for the scheduler's single
cross-tenant read, and `tests/database/test_scheduling_seam.py` for the assertions that
the confinement holds.

## Operationally

```
SIEMBIOT_DATABASE_URL=…siembiot_owner…         # migrations only
SIEMBIOT_APP_DATABASE_URL=…siembiot_app…       # the API
SIEMBIOT_WORKER_DATABASE_URL=…siembiot_worker… # the worker
```

Three separate passwords. Sharing one between the API and the worker would hand the API
the worker's membership-free write permission, and sharing either with the owner would
switch row-level security off.
