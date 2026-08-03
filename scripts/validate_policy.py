from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from siembiot_worker.evaluation.policy import load_policy_catalog


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    policy_root = root / "packages" / "policy"
    catalog_path = policy_root / "checks" / "v1"
    schema_path = policy_root / "schema" / "v1"
    check_schema = json.loads((schema_path / "check.schema.json").read_text(encoding="utf-8"))
    methodology_schema = json.loads(
        (schema_path / "methodology.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(check_schema)
    Draft202012Validator.check_schema(methodology_schema)
    Draft202012Validator(methodology_schema).validate(
        json.loads((catalog_path / "methodology.json").read_text(encoding="utf-8"))
    )
    for file in sorted(catalog_path.glob("*.json")):
        if file.name in {"methodology.json", "references.json"}:
            continue
        document = json.loads(file.read_text(encoding="utf-8"))
        for check in document.get("checks", []):
            Draft202012Validator(check_schema).validate(check)
    catalog = load_policy_catalog(catalog_path)
    print(
        f"Policy {catalog.methodology_version} verified: {catalog.policy_hash}; "
        f"{len(catalog.checks)} checks; {len(catalog.pillars)} pillars."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
