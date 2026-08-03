from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from siembiot_worker.evidence.models import EvaluationOutcome

RuleResult = tuple[EvaluationOutcome, str]


def _boolean_secure(payload: Mapping[str, Any]) -> RuleResult:
    secure = payload.get("secure")
    if isinstance(secure, bool):
        return (
            (EvaluationOutcome.PASS, "control_present")
            if secure
            else (
                EvaluationOutcome.FAIL,
                "control_missing",
            )
        )
    records = payload.get("records")
    if isinstance(records, list | tuple):
        return (
            (EvaluationOutcome.PASS, "control_present")
            if records
            else (
                EvaluationOutcome.FAIL,
                "control_missing",
            )
        )
    return EvaluationOutcome.UNKNOWN, "insufficient_evidence"


def _policy_strength(payload: Mapping[str, Any]) -> RuleResult:
    policy = str(payload.get("policy", "")).lower()
    if policy == "reject":
        return EvaluationOutcome.PASS, "enforcing_policy"
    if policy == "quarantine":
        return EvaluationOutcome.WARNING, "partial_policy"
    if policy in {"none", "absent"}:
        return EvaluationOutcome.FAIL, "non_enforcing_policy"
    return EvaluationOutcome.UNKNOWN, "insufficient_evidence"


def _header_present(payload: Mapping[str, Any]) -> RuleResult:
    headers = payload.get("headers")
    if not isinstance(headers, Mapping):
        return EvaluationOutcome.UNKNOWN, "insufficient_evidence"
    present = headers.get("hsts") is True or "strict-transport-security" in headers
    return (
        (EvaluationOutcome.PASS, "required_header_present")
        if present
        else (
            EvaluationOutcome.FAIL,
            "required_header_missing",
        )
    )


def _attribution_review(payload: Mapping[str, Any]) -> RuleResult:
    if payload.get("asset_authorized") is True:
        return EvaluationOutcome.PASS, "asset_authorized"
    return EvaluationOutcome.UNKNOWN, "attribution_review_required"


def _provider_signal(payload: Mapping[str, Any]) -> RuleResult:
    signal = payload.get("malicious")
    if signal is True:
        return EvaluationOutcome.FAIL, "corroborated_abuse_signal"
    if signal is False:
        return EvaluationOutcome.PASS, "no_abuse_signal"
    return EvaluationOutcome.UNKNOWN, "provider_unavailable"


def _registration_freshness(payload: Mapping[str, Any]) -> RuleResult:
    status = payload.get("status")
    values = {str(item).lower() for item in status} if isinstance(status, list | tuple) else set()
    if "active" in values:
        return EvaluationOutcome.PASS, "registration_active"
    return (
        (EvaluationOutcome.WARNING, "registration_review_required")
        if values
        else (
            EvaluationOutcome.UNKNOWN,
            "insufficient_evidence",
        )
    )


RULES = {
    "boolean_secure": _boolean_secure,
    "policy_strength": _policy_strength,
    "header_present": _header_present,
    "attribution_review": _attribution_review,
    "provider_signal": _provider_signal,
    "registration_freshness": _registration_freshness,
}


def evaluate_rule(rule: str, payload: Mapping[str, Any]) -> RuleResult:
    if payload.get("applicable") is False:
        return EvaluationOutcome.NOT_APPLICABLE, "not_applicable"
    evaluator = RULES.get(rule)
    if evaluator is None:
        raise ValueError("unsupported_result_rule")
    return evaluator(payload)
