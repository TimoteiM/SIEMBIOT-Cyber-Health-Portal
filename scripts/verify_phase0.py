"""Dependency-free structural checks for the Phase 0 design baseline."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = {
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/product/repository-audit.md",
    "docs/product/product-specification.md",
    "docs/architecture/target-architecture.md",
    "docs/architecture/tyche-adaptation.md",
    "docs/security/threat-model.md",
    "docs/methodology/methodology-specification.md",
    "docs/knowledge-base/source-register.md",
    "docs/plans/2026-08-03-siem-biot-design.md",
    "docs/plans/2026-08-03-production-implementation-plan.md",
}
REQUIRED_ADRS = {f"docs/adr/{number:04d}" for number in range(1, 12)}
REQUIRED_TERMS = {
    "docs/architecture/target-architecture.md": (
        "trust boundaries",
        "signed immutable scope manifest",
        "public projection",
        "deterministic",
    ),
    "docs/security/threat-model.md": (
        "cross-tenant",
        "out-of-scope",
        "prompt injection",
        "DNS rebinding",
    ),
    "docs/product/repository-audit.md": (
        "2609c7effcf24ee63147386bb378e2f3b4ce2e9d",
        "read-only",
        "credential exposure",
    ),
}
SECRET_PATTERNS = (
    re.compile(r"(?i)(password|passwd|secret|api[_-]?key)\s*[:=]\s*['\"][^<'\"]{4,}"),
    re.compile(r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


def fail(message: str, errors: list[str]) -> None:
    errors.append(message)


def main() -> int:
    errors: list[str] = []
    files = {
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_file() and ".git" not in path.parts
    }

    for required in sorted(REQUIRED_FILES - files):
        fail(f"missing required file: {required}", errors)

    for prefix in sorted(REQUIRED_ADRS):
        if not any(path.startswith(prefix + "-") and path.endswith(".md") for path in files):
            fail(f"missing ADR prefix: {prefix}", errors)

    for relative, terms in REQUIRED_TERMS.items():
        text = (ROOT / relative).read_text(encoding="utf-8").lower()
        for term in terms:
            if term.lower() not in text:
                fail(f"{relative} missing term: {term}", errors)

    for relative in sorted(
        path for path in files if path.endswith((".md", ".yml", ".yaml", ".py"))
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        if text.count("```mermaid") > text.count("```"):
            fail(f"unclosed Mermaid fence: {relative}", errors)
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                fail(f"possible committed secret in {relative}", errors)

    if errors:
        print("Phase 0 verification failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"Phase 0 verification passed: {len(files)} files, 11 ADRs, no structural errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
