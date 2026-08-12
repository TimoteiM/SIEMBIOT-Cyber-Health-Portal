"""A provider quota that every worker shares.

`QuotaLedger` counts in one process's memory. With four workers and a limit of a thousand
calls a day, the platform will make four thousand — each worker believing it stayed inside
the budget, and the provider seeing something quite different. A budget that is only
per-process is not a budget.

Redis holds the counter because every worker already talks to it, and because the
arithmetic has to be atomic across processes: read-then-write would let two workers see
the same remaining count and both spend it. The consume is a Lua script, so the check and
the increment happen together or not at all.

The window is a calendar day in UTC, and the key carries it. That makes the reset free --
tomorrow's key simply does not exist yet -- and it means a stuck counter cannot poison
more than a day.

**This does not read from Postgres and Postgres does not read from it.** A periodic
snapshot copies the day's counters into the database for history and for the metrics
endpoint, which is the only path by which quota becomes something a dashboard or an alert
can see. Redis is the live truth; Postgres is the record.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

KEY_PREFIX = "siembiot:quota"

#: Two days. Long enough that the snapshot task has many chances to record a day before
#: it disappears, short enough that a Redis restarted after a week is not carrying
#: counters nobody will ever look at.
KEY_TTL_SECONDS = 172_800

#: Consume atomically, or refuse without consuming.
#:
#: The `denied` counter is incremented on refusal in the same script, because a refusal
#: that is not counted is a budget that looks like it was never approached: an operator
#: seeing `used == limit` cannot tell one call turned away from ten thousand.
_CONSUME = """
local used_key = KEYS[1]
local denied_key = KEYS[2]
local limit = tonumber(ARGV[1])
local units = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])

local used = tonumber(redis.call('GET', used_key) or '0')

if limit >= 0 and used + units > limit then
    redis.call('INCRBY', denied_key, units)
    redis.call('EXPIRE', denied_key, ttl)
    return {0, used}
end

local now = redis.call('INCRBY', used_key, units)
redis.call('EXPIRE', used_key, ttl)
return {1, now}
"""


#: Give back units, never below zero. A negative counter would present itself as
#: capacity nobody has.
_REFUND = """
local used_key = KEYS[1]
local units = tonumber(ARGV[1])
local used = tonumber(redis.call('GET', used_key) or '0')
local next_value = used - units
if next_value < 0 then next_value = 0 end
redis.call('SET', used_key, next_value)
return next_value
"""


class RedisLike(Protocol):
    """What this needs from Redis, and nothing more.

    Narrow on purpose: the worker's Redis client is a Celery dependency, and a protocol
    this small can be satisfied by a fake in a test without pretending to be Redis.
    """

    def eval(self, script: str, numkeys: int, *args: Any) -> Any: ...

    def get(self, name: str) -> Any: ...

    def scan_iter(self, match: str) -> Any: ...


def window_for(moment: datetime | None = None) -> str:
    return (moment or datetime.now(UTC)).strftime("%Y-%m-%d")


def used_key(adapter_id: str, window: str) -> str:
    return f"{KEY_PREFIX}:{adapter_id}:{window}:used"


def denied_key(adapter_id: str, window: str) -> str:
    return f"{KEY_PREFIX}:{adapter_id}:{window}:denied"


@dataclass
class SharedQuotaLedger:
    """The same interface `QuotaLedger` presents, backed by a counter every worker shares.

    `limit=None` means unmetered, and is passed to the script as -1 rather than being
    special-cased here: one branch in one place, and it is the place that is atomic.
    """

    redis: RedisLike
    adapter_id: str
    limit: int | None = None

    def try_consume(self, units: int = 1) -> bool:
        if units < 1:
            raise ValueError("invalid_quota_units")
        allowed, _ = self._consume(units)
        return allowed

    def _consume(self, units: int) -> tuple[bool, int]:
        window = window_for()
        result = self.redis.eval(
            _CONSUME,
            2,
            used_key(self.adapter_id, window),
            denied_key(self.adapter_id, window),
            -1 if self.limit is None else self.limit,
            units,
            KEY_TTL_SECONDS,
        )
        allowed, used = int(result[0]), int(result[1])
        return bool(allowed), used

    def refund(self, units: int = 1) -> None:
        """Give back units charged for a call that never happened.

        The guard takes quota before the rate limiter, so a call the limiter turns away
        has already been charged. `DECRBY` rather than a read-modify-write, for the same
        reason the consume is a script: another worker is spending the same counter.

        Floored at zero by the refund script, because a negative budget would read as
        capacity that does not exist.
        """
        if units < 1:
            raise ValueError("invalid_quota_units")
        self.redis.eval(_REFUND, 1, used_key(self.adapter_id, window_for()), units)

    @property
    def used(self) -> int:
        return _count(self.redis, used_key(self.adapter_id, window_for()))

    @property
    def denied(self) -> int:
        return _count(self.redis, denied_key(self.adapter_id, window_for()))

    @property
    def remaining(self) -> int | None:
        return None if self.limit is None else max(0, self.limit - self.used)

    @property
    def exhausted(self) -> bool:
        return self.remaining == 0


def _count(redis: RedisLike, key: str) -> int:
    raw = redis.get(key)
    if raw is None:
        return 0
    return int(raw.decode() if isinstance(raw, bytes) else raw)


@dataclass(frozen=True)
class QuotaReading:
    adapter_id: str
    window: str
    used: int
    denied: int


def read_all(redis: RedisLike, window: str | None = None) -> tuple[QuotaReading, ...]:
    """Every adapter's counters for one day, for the snapshot task.

    Scanned rather than read from a list of adapter names: an adapter that started
    spending quota without anybody adding it to a registry is exactly the one worth
    seeing, and a name-driven read would miss it.
    """
    target = window or window_for()
    readings: dict[str, dict[str, int]] = {}

    for raw_key in redis.scan_iter(f"{KEY_PREFIX}:*:{target}:*"):
        key = raw_key.decode() if isinstance(raw_key, bytes) else str(raw_key)
        parts = key.split(":")
        if len(parts) != 5:
            continue
        adapter_id, kind = parts[2], parts[4]
        entry = readings.setdefault(adapter_id, {"used": 0, "denied": 0})
        if kind in entry:
            entry[kind] = _count(redis, key)

    return tuple(
        QuotaReading(adapter_id, target, counts["used"], counts["denied"])
        for adapter_id, counts in sorted(readings.items())
    )
