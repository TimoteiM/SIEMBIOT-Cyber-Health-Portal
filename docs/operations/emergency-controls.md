# Emergency Controls Runbook

## Available controls

- `global`: blocks every brokered HTTPS ownership check; activation/deactivation requires a platform administrator with phishing-resistant MFA assurance.
- `organization`: blocks network operations for one tenant.
- `domain`: blocks one exact tenant-owned domain.
- `operation_class`: blocks the selected operation class for one tenant.

Organization owners and security administrators may manage tenant controls. Analysts and auditors may read them but cannot activate or deactivate them. PostgreSQL RLS independently enforces tenant visibility and the global-admin requirement.

## Activate

Use the authenticated API or Romanian portal, select the narrowest effective scope, supply a security-relevant reason of 10–500 characters, and optionally set a future expiry. Confirm the returned control is active and inspect the immutable `emergency_control.activated` audit event. Do not put credentials, challenge values, target response bodies, or sensitive findings in the reason.

The database policy is re-read before DNS resolution, after resolution, before connect, after response headers, during body reads, and before redirects. A newly active control therefore rejects queued/synchronous work before connection and cooperatively cancels an in-flight bounded read at its next checkpoint.

## Recover

Investigate and contain the initiating condition before deactivation. Record a distinct recovery reason, deactivate through the same scope, confirm the audit event, then perform one fictional/reserved-domain verification smoke test. Recovery does not revive expired/revoked challenges or authorizations; operators must create new authority where required.

## Escalation and evidence

Retain control ID, scope, actor, request/correlation ID, activation/deactivation time, reason, and outcome. Network decision records deliberately omit resolved IP addresses, response bodies, and ownership tokens. If a control is ineffective, activate the broader control, restrict workload egress at the deployment layer, and treat the event as a release/security incident.
