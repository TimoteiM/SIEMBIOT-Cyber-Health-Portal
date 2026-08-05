"""E-mail trust collection (pillar B).

DKIM selectors are only ever those the organization declared or a provider's own
metadata supplied — the collector never brute-forces a selector wordlist. BIMI is
collected as informational context and is deliberately not a security control.
"""

from __future__ import annotations

import re
from typing import Any

from siembiot_worker.adapters.contract import (
    AdapterDescriptor,
    AdapterGroup,
    CachePolicy,
    CollectionResult,
    CostUnit,
    DataClassification,
    RateLimitPolicy,
)
from siembiot_worker.collectors.base import Collector, inconclusive_reasons, record_set_payload
from siembiot_worker.network_safety.collection_broker import CollectionRequest
from siembiot_worker.network_safety.collection_policy import OperationClass, https_destination
from siembiot_worker.network_safety.dns_client import DNSRecordSet

SPF_LOOKUP_LIMIT = 10
SPF_VOID_LOOKUP_LIMIT = 2
MAX_DECLARED_SELECTORS = 10
_SPF_LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists", "redirect")
_PERMISSIVE_ALL = {"+all", "all"}
_SOFT_ALL = {"~all", "?all"}
_MTA_STS_LINE = re.compile(r"^(?P<key>[a-z_]+):\s*(?P<value>.+?)\s*$", re.IGNORECASE)

EMAIL_DESCRIPTOR = AdapterDescriptor(
    adapter_id="email_trust",
    version="1.0.0",
    group=AdapterGroup.DNS_RDAP,
    title="E-mail trust collector",
    capabilities=frozenset(
        {
            "email.spf",
            "email.dmarc",
            "email.dkim_declared",
            "email.mta_sts",
            "email.tls_rpt",
            "email.dane",
            "email.bimi",
            "email.mx",
        }
    ),
    data_classification=DataClassification.PUBLIC_OBSERVATION,
    terms_notes="Public DNS policy records and the published MTA-STS policy file.",
    terms_url=None,
    required_secrets=frozenset(),
    timeout_seconds=6.0,
    rate_limit=RateLimitPolicy(20, 1.0, burst=10),
    cost_unit=CostUnit.NONE,
    cache=CachePolicy(300),
    supports_fixtures=True,
)


def select_policy_record(records: tuple[str, ...], prefix: str) -> tuple[str | None, int]:
    """Return the single matching policy record; more than one is itself a finding."""
    matches = [record for record in records if record.lower().startswith(prefix.lower())]
    if len(matches) != 1:
        return None, len(matches)
    return matches[0], 1


def parse_spf(record: str) -> dict[str, Any]:
    """Count lookups and flag permissiveness; evaluation of the result happens later."""
    terms = record.split()
    mechanisms: list[str] = []
    lookups = 0
    includes: list[str] = []
    redirect: str | None = None
    syntax_errors: list[str] = []
    all_qualifier: str | None = None
    for term in terms[1:]:
        lowered = term.lower()
        mechanisms.append(term)
        name = lowered.split(":", 1)[0].split("=", 1)[0].lstrip("+-~?")
        if name in _SPF_LOOKUP_MECHANISMS:
            lookups += 1
        if name == "include":
            if ":" not in term:
                syntax_errors.append(term)
            else:
                includes.append(term.split(":", 1)[1])
        if lowered.startswith("redirect="):
            redirect = term.split("=", 1)[1]
        if lowered.endswith("all") and name == "all":
            all_qualifier = lowered
    if not terms or terms[0].lower() != "v=spf1":
        syntax_errors.append("missing_version")
    return {
        "record": record,
        "mechanisms": mechanisms,
        "dns_lookup_count": lookups,
        "exceeds_lookup_limit": lookups > SPF_LOOKUP_LIMIT,
        "includes": includes,
        "redirect": redirect,
        "all_qualifier": all_qualifier,
        "permissive_all": all_qualifier in _PERMISSIVE_ALL,
        "soft_all": all_qualifier in _SOFT_ALL,
        "has_ptr_mechanism": any(
            term.lower().lstrip("+-~?").startswith("ptr") for term in mechanisms
        ),
        "syntax_errors": syntax_errors,
        "valid": not syntax_errors,
    }


def parse_tag_record(record: str) -> tuple[dict[str, str], list[str]]:
    tags: dict[str, str] = {}
    errors: list[str] = []
    for part in record.split(";"):
        candidate = part.strip()
        if not candidate:
            continue
        if "=" not in candidate:
            errors.append(candidate)
            continue
        key, value = candidate.split("=", 1)
        key = key.strip().lower()
        if key in tags:
            errors.append(f"duplicate_tag:{key}")
            continue
        tags[key] = value.strip()
    return tags, errors


def _reporting_domain(address: str) -> str:
    """Strip the optional ``!size`` limit before reading the reporting domain."""
    return address.split("@", 1)[1].split("!", 1)[0].rstrip(".").lower()


def parse_dmarc(record: str) -> dict[str, Any]:
    tags, errors = parse_tag_record(record)
    policy = tags.get("p", "").lower() or None
    subdomain_policy = tags.get("sp", "").lower() or None
    percentage_raw = tags.get("pct")
    percentage: int | None = None
    if percentage_raw is not None:
        try:
            percentage = int(percentage_raw)
        except ValueError:
            errors.append("invalid_pct")
    rua = [item.strip() for item in tags.get("rua", "").split(",") if item.strip()]
    ruf = [item.strip() for item in tags.get("ruf", "").split(",") if item.strip()]
    external_domains = sorted(
        {
            _reporting_domain(address)
            for address in rua + ruf
            if address.lower().startswith("mailto:") and "@" in address
        }
    )
    if tags.get("v", "").upper() != "DMARC1":
        errors.append("missing_version")
    if policy not in {"none", "quarantine", "reject"}:
        errors.append("invalid_policy")
    return {
        "record": record,
        "tags": tags,
        "policy": policy,
        "subdomain_policy": subdomain_policy,
        "percentage": percentage,
        "adkim": tags.get("adkim", "r").lower(),
        "aspf": tags.get("aspf", "r").lower(),
        "aggregate_reporting_addresses": rua,
        "forensic_reporting_addresses": ruf,
        "external_report_domains": external_domains,
        "external_authorization_required": bool(external_domains),
        "syntax_errors": errors,
        "valid": not errors,
    }


def parse_mta_sts_policy(body: str) -> dict[str, Any]:
    """Parse the published policy file; malformed input stays malformed, not absent."""
    version: str | None = None
    mode: str | None = None
    max_age: int | None = None
    mx_patterns: list[str] = []
    errors: list[str] = []
    for line in body.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        match = _MTA_STS_LINE.match(candidate)
        if match is None:
            errors.append(candidate[:64])
            continue
        key = match.group("key").lower()
        value = match.group("value")
        if key == "version":
            version = value
        elif key == "mode":
            mode = value.lower()
        elif key == "max_age":
            try:
                max_age = int(value)
            except ValueError:
                errors.append("invalid_max_age")
        elif key == "mx":
            mx_patterns.append(value.lower())
        else:
            errors.append(f"unknown_key:{key}")
    if version != "STSv1":
        errors.append("invalid_version")
    if mode not in {"none", "testing", "enforce"}:
        errors.append("invalid_mode")
    return {
        "version": version,
        "mode": mode,
        "max_age_seconds": max_age,
        "mx_patterns": mx_patterns,
        "syntax_errors": errors,
        "valid": not errors,
    }


class EmailTrustCollector(Collector):
    descriptor = EMAIL_DESCRIPTOR

    def collect(
        self,
        request: CollectionRequest,
        *,
        declared_dkim_selectors: tuple[str, ...] = (),
    ) -> CollectionResult:
        host = request.canonical_host
        answers: dict[str, DNSRecordSet] = {
            "mx": self._broker.query_dns(request, host, "MX"),
            "spf": self._broker.query_dns(request, host, "TXT"),
            "dmarc": self._broker.query_dns(request, f"_dmarc.{host}", "TXT"),
            "mta_sts": self._broker.query_dns(request, f"_mta-sts.{host}", "TXT"),
            "tls_rpt": self._broker.query_dns(request, f"_smtp._tls.{host}", "TXT"),
            "bimi": self._broker.query_dns(request, f"default._bimi.{host}", "TXT"),
        }

        payload: dict[str, Any] = {
            "host": host,
            "mx": self._mx_payload(answers["mx"]),
            "spf": self._spf_payload(answers["spf"]),
            "dmarc": self._dmarc_payload(answers["dmarc"]),
            "mta_sts": self._mta_sts_payload(request, answers["mta_sts"]),
            "tls_rpt": self._tls_rpt_payload(answers["tls_rpt"]),
            "bimi": self._bimi_payload(answers["bimi"]),
        }
        dkim, dkim_answers = self._dkim_payload(request, declared_dkim_selectors)
        payload["dkim"] = dkim
        answers.update(dkim_answers)
        payload["dane"], dane_answers = self._dane_payload(request, answers["mx"])
        answers.update(dane_answers)
        payload["lookups"] = {key: record_set_payload(value) for key, value in answers.items()}

        reasons = inconclusive_reasons(answers)
        if not answers["spf"].is_conclusive and not answers["dmarc"].is_conclusive:
            return self.unavailable("dns_unreachable", payload)
        if reasons:
            return self.partial(payload, reasons, source=host)
        return self.ok(payload, source=host)

    # -- sections ------------------------------------------------------------

    @staticmethod
    def _mx_payload(answer: DNSRecordSet) -> dict[str, Any]:
        hosts: list[dict[str, Any]] = []
        for record in answer.records:
            parts = record.split()
            if len(parts) != 2 or not parts[0].isdigit():
                continue
            hosts.append({"preference": int(parts[0]), "exchange": parts[1].rstrip(".").lower()})
        hosts.sort(key=lambda item: (item["preference"], item["exchange"]))
        return {
            "present": answer.is_answered,
            "conclusive": answer.is_conclusive,
            "hosts": hosts,
            "null_mx": len(hosts) == 1 and hosts[0]["exchange"] == "",
        }

    @staticmethod
    def _spf_payload(answer: DNSRecordSet) -> dict[str, Any]:
        record, count = select_policy_record(answer.records, "v=spf1")
        if record is None:
            return {
                "present": False,
                "conclusive": answer.is_conclusive,
                "matching_record_count": count,
                "multiple_records": count > 1,
                "parsed": None,
            }
        return {
            "present": True,
            "conclusive": answer.is_conclusive,
            "matching_record_count": count,
            "multiple_records": False,
            "parsed": parse_spf(record),
        }

    @staticmethod
    def _dmarc_payload(answer: DNSRecordSet) -> dict[str, Any]:
        record, count = select_policy_record(answer.records, "v=DMARC1")
        if record is None:
            return {
                "present": False,
                "conclusive": answer.is_conclusive,
                "matching_record_count": count,
                "multiple_records": count > 1,
                "parsed": None,
            }
        return {
            "present": True,
            "conclusive": answer.is_conclusive,
            "matching_record_count": count,
            "multiple_records": False,
            "parsed": parse_dmarc(record),
        }

    def _mta_sts_payload(self, request: CollectionRequest, answer: DNSRecordSet) -> dict[str, Any]:
        record, count = select_policy_record(answer.records, "v=STSv1")
        section: dict[str, Any] = {
            "dns_record_present": record is not None,
            "conclusive": answer.is_conclusive,
            "matching_record_count": count,
            "policy_id": None,
            "policy": None,
            "policy_fetch_reason": None,
        }
        if record is None:
            return section
        tags, _ = parse_tag_record(record)
        section["policy_id"] = tags.get("id")
        policy_host = f"mta-sts.{request.canonical_host}"
        fetch_request = CollectionRequest(
            request.organization_id,
            request.domain_id,
            request.assessment_id,
            OperationClass.EMAIL_POLICY_FETCH,
            policy_host,
            (policy_host,),
        )
        result = self._broker.fetch(
            fetch_request, https_destination(OperationClass.EMAIL_POLICY_FETCH, policy_host)
        )
        if not result.allowed:
            section["policy_fetch_reason"] = result.reason_code
            return section
        if result.status_code != 200:
            section["policy_fetch_reason"] = f"http_status_{result.status_code}"
            return section
        try:
            body = result.body.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            section["policy_fetch_reason"] = "invalid_encoding"
            return section
        section["policy"] = parse_mta_sts_policy(body)
        section["policy_fetch_reason"] = "fetched"
        return section

    @staticmethod
    def _tls_rpt_payload(answer: DNSRecordSet) -> dict[str, Any]:
        record, count = select_policy_record(answer.records, "v=TLSRPTv1")
        if record is None:
            return {"present": False, "conclusive": answer.is_conclusive, "destinations": []}
        tags, errors = parse_tag_record(record)
        destinations = [item.strip() for item in tags.get("rua", "").split(",") if item.strip()]
        return {
            "present": True,
            "conclusive": answer.is_conclusive,
            "matching_record_count": count,
            "destinations": destinations,
            "syntax_errors": errors,
            "valid": not errors and bool(destinations),
        }

    @staticmethod
    def _bimi_payload(answer: DNSRecordSet) -> dict[str, Any]:
        record, _ = select_policy_record(answer.records, "v=BIMI1")
        return {
            "present": record is not None,
            "conclusive": answer.is_conclusive,
            "informational_only": True,
            "record": record,
        }

    def _dkim_payload(
        self, request: CollectionRequest, declared_selectors: tuple[str, ...]
    ) -> tuple[dict[str, Any], dict[str, DNSRecordSet]]:
        answers: dict[str, DNSRecordSet] = {}
        if not declared_selectors:
            return (
                {
                    "selector_source": "none_declared",
                    "selectors": [],
                    "note": "Selectors are never guessed; declare them to enable DKIM checks.",
                },
                answers,
            )
        selectors: list[dict[str, Any]] = []
        for selector in sorted(set(declared_selectors))[:MAX_DECLARED_SELECTORS]:
            name = f"{selector}._domainkey.{request.canonical_host}"
            answer = self._broker.query_dns(request, name, "TXT")
            answers[f"dkim_{selector}"] = answer
            record, _ = select_policy_record(answer.records, "v=DKIM1")
            tags, errors = parse_tag_record(record) if record else ({}, [])
            selectors.append(
                {
                    "selector": selector,
                    "name": name,
                    "present": record is not None,
                    "conclusive": answer.is_conclusive,
                    "key_type": tags.get("k", "rsa" if record else None),
                    "revoked": record is not None and tags.get("p", "") == "",
                    "syntax_errors": errors,
                }
            )
        return (
            {
                "selector_source": "declared",
                "selectors": selectors,
                "truncated": len(set(declared_selectors)) > MAX_DECLARED_SELECTORS,
            },
            answers,
        )

    def _dane_payload(
        self, request: CollectionRequest, mx_answer: DNSRecordSet
    ) -> tuple[dict[str, Any], dict[str, DNSRecordSet]]:
        answers: dict[str, DNSRecordSet] = {}
        if not mx_answer.is_answered:
            return (
                {"applicable": False, "reason": "no_mx_hosts", "hosts": []},
                answers,
            )
        hosts: list[dict[str, Any]] = []
        for record in mx_answer.records[:5]:
            parts = record.split()
            if len(parts) != 2 or not parts[0].isdigit():
                continue
            exchange = parts[1].rstrip(".").lower()
            if not exchange:
                continue
            name = f"_25._tcp.{exchange}"
            answer = self._broker.query_dns(request, name, "TLSA")
            answers[f"tlsa_{exchange}"] = answer
            hosts.append(
                {
                    "mx_host": exchange,
                    "name": name,
                    "present": answer.is_answered,
                    "conclusive": answer.is_conclusive,
                    "record_count": len(answer.records),
                }
            )
        return ({"applicable": True, "hosts": hosts}, answers)
