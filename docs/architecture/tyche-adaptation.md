# Tyche Pattern Adaptation Boundary

## Adapt through clean reimplementation

| Confirmed pattern | SIEMBIOT form | Required hardening |
| --- | --- | --- |
| Semantic Kernel construction | Provider-neutral internal `AgentGateway` | per-run provider/model pin, structured schemas, deadlines, token/cost budgets |
| Plugin registration | Versioned `ToolDescriptor` registry | deny by default, capability tags, scope preconditions, pure validation |
| Specialized agents | bounded planner/analyst/report roles | no peer-to-peer authority expansion; deterministic state machine owns stages |
| Sequential orchestration | explicit workflow step graph | durable state, idempotency, cancellation, retries, audit events |
| Tool descriptions | policy-owned catalog metadata | content is data, never instructions; integrity/version checks |

## Reject

- CRM, account, invoice, credit, ticket, prioritization, and e-mail business logic;
- React UI, CSS, Express server, SQL queries, Azure SQL schema, sample HTTP calls, and commented chat UI;
- Tyche Git history, lockfiles, requirements, environment samples, deployment artifacts, provider values, and credentials;
- direct network access from plugins or model-facing code;
- string-only tool results and free-form agent responses;
- global environment configuration loaded at import time;
- wildcard CORS, exception detail leakage, provider-specific coupling, and unauthenticated endpoints;
- model-led scoring, evidence mutation, open-ended tool choice, and implicit trust in retrieved content.

## Integration invariant

The Tyche-derived agent layer has no direct route to DNS, HTTP, SMTP, storage, database, queue, e-mail, or tenant secrets. It receives a minimal redacted evidence view and a signed scope reference, returns schema-validated proposals/narrative, and can request only registered tool capabilities. The workflow/policy service independently authorizes every request and deterministic workers perform any permitted operation.
