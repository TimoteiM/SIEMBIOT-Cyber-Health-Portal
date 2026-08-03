from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "worker" / "src"))

from siembiot_worker.collection.fixtures import FixtureScenarioPack  # noqa: E402


def main() -> int:
    root = ROOT / "tests" / "fixtures" / "fake_internet" / "v1"
    pack = FixtureScenarioPack.load(root)
    scenario_ids = ", ".join(sorted(item.id for item in pack.scenarios))
    print(f"Fixture pack {pack.version} verified: sha256:{pack.digest}; scenarios: {scenario_ids}")
    print("No service started and no network connection attempted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
