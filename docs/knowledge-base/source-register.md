# Authoritative Source Register

**Retrieved/reviewed:** 2026-08-03
**Policy:** use canonical primary sources, store version/date and applicable check IDs, review at the interval below, and fail methodology release when a required source is expired without disposition. The register is guidance provenance, not legal advice.

| ID | Title / publisher | Version/date | Canonical URL | Applies to | Review |
| --- | --- | --- | --- | --- | --- |
| LEG-EU-NIS2 | Directive (EU) 2022/2555 / EU | 2022-12-14; consolidated 2022-12-27 | https://eur-lex.europa.eu/eli/dir/2022/2555/oj | maturity mappings, limitations | 90d |
| LEG-RO-OUG155 | OUG 155/2024 consolidated / Romania | 2024-12-30, as amended through current portal form | https://legislatie.just.ro/Public/DetaliiDocumentAfis/311690 | Romanian implementation context | 30d |
| LEG-RO-L124 | Law 124/2025 / Romania | 2025-07-07 | https://legislatie.just.ro/Public/DetaliiDocument/299675 | OUG approval/amendments | 30d |
| LEG-RO-NORMS | DNSC supervision/control norms / DNSC | 2025-11-27 | https://legislatie.just.ro/Public/DetaliiDocument/305129 | legal/operations context | 30d |
| LEG-RO-L123 | Law 123/2026 / Romania | 2026-07-03 | https://legislatie.just.ro/Public/DetaliiDocumentAfis/312027 | vulnerability research/authorization counsel review | 30d |
| RFC-SPF | Sender Policy Framework / IETF | RFC 7208, 2014-04 | https://www.rfc-editor.org/info/rfc7208 | SPF parsing/evaluation | 180d |
| RFC-DKIM | DKIM / IETF | RFC 6376 + RFC 8301 + RFC 8463 | https://www.rfc-editor.org/info/rfc6376 | declared DKIM selectors/key posture | 180d |
| RFC-DMARC | DMARC / IETF | RFC 9989, 2026-06 | https://www.rfc-editor.org/info/rfc9989 | DMARC syntax/policy/alignment/reporting | 90d |
| RFC-MTASTS | MTA-STS / IETF | RFC 8461, 2018-09 | https://www.rfc-editor.org/info/rfc8461 | MTA-STS | 180d |
| RFC-TLSRPT | SMTP TLS Reporting / IETF | RFC 8460, 2018-09 | https://www.rfc-editor.org/info/rfc8460 | TLS-RPT | 180d |
| RFC-DNSSEC | DNSSEC intro/protocol/modifications / IETF | RFC 4033/4034/4035, RFC 9364 | https://www.rfc-editor.org/info/rfc4033 | DNSSEC presence/validation | 180d |
| RFC-DANE | TLSA and SMTP DANE / IETF | RFC 6698 + RFC 7672 | https://www.rfc-editor.org/info/rfc7672 | DANE/TLSA | 180d |
| RFC-CAA | CAA processing / IETF | RFC 8659, 2019-11 | https://www.rfc-editor.org/info/rfc8659 | CAA | 180d |
| RFC-RDAP | RDAP query/response / IETF | RFC 9082 + RFC 9083, 2021-06 | https://www.rfc-editor.org/info/rfc9082 | registration/expiry signals | 180d |
| RFC-CT | Certificate Transparency v2 / IETF | RFC 9162, 2021-12 | https://www.rfc-editor.org/info/rfc9162 | CT observations/assets | 180d |
| RFC-TLS | TLS 1.3 / IETF | RFC 8446, 2018-08 | https://www.rfc-editor.org/info/rfc8446 | safe TLS handshakes | 180d |
| PSL | Public Suffix List / community/Mozilla initiative | daily list | https://publicsuffix.org/list/ | registrable-domain calculation | 30d; fetch max daily |
| MOZ-TLS | Mozilla SSL Configuration Generator / Mozilla | current generator | https://ssl-config.mozilla.org/ | versioned TLS baseline | 90d |
| MOZ-HTTP | MDN HTTP Observatory tests/guidance / Mozilla | current | https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring | HTTP headers; do not copy its score | 90d |
| OWASP-SSRF | SSRF Prevention Cheat Sheet / OWASP | current | https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html | centralized network safety | 90d |
| OWASP-AUTH | Authentication Cheat Sheet / OWASP | current | https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html | authentication | 90d |
| OWASP-SESS | Session Management Cheat Sheet / OWASP | current | https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html | sessions | 90d |
| OWASP-UPLOAD | File Upload Cheat Sheet / OWASP | current | https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html | evidence upload | 90d |
| OWASP-LOG | Logging Cheat Sheet / OWASP | current | https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html | audit/logging | 90d |
| OWASP-LLM | LLM Prompt Injection Prevention Cheat Sheet / OWASP | current | https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html | agent boundary | 60d |
| OWASP-MT | Multi-Tenant Security Cheat Sheet / OWASP | current | https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html | tenant isolation | 90d |
| CIS-81 | CIS Critical Security Controls / CIS | v8.1, 2024-06 | https://www.cisecurity.org/controls/v8-1 | optional maturity IG1 mapping | 180d/license review |

## Notes from current review

- RFC 9989 is the current DMARC RFC and supersedes the older RFC 7489 baseline; implementation must not start from stale DMARC snippets.
- Romanian OUG 155/2024 has later approval, norms, and July 2026 amendment context; counsel must review the consolidated legal position before launch.
- CIS materials have usage terms. Store only identifiers/mappings permitted by those terms; do not redistribute restricted content.
- Mozilla Observatory is an input/reference, not SIEMBIOT's scoring formula or proof that a site is secure.
