from __future__ import annotations

import json

from siembiot_worker.scoring.reproduction import reproduce


def main() -> int:
    output = reproduce()
    print(json.dumps(output, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
