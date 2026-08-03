# ADR-0011: Deployment and Observability

**Status:** Accepted — 2026-08-03

## Decision

Ship deterministic Docker Compose locally and pinned, minimal, non-root OCI images for production. Provide vendor-neutral Kubernetes-compatible manifests/network policies; managed PostgreSQL/Redis/S3/OIDC may replace community services. Secrets enter from a secret manager at runtime.

Use OpenTelemetry for traces/metrics/log correlation; Prometheus-compatible metrics and Grafana dashboards are the default community stack. Structured logs redact secrets, personal data, raw payloads, and private findings. Release CI produces SBOM, signed images/provenance, migration checks, security scans, and smoke tests.

## Consequences

Operational parity is explicit but local Compose is not presented as a high-availability production topology. Dashboards cover API, queue, provider, model, verification abuse, reports, public health, and privacy-safe usage metrics.
