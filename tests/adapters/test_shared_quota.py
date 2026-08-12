"""A provider budget that every worker shares.

The in-memory ledger counted in one process. With four workers and a limit of a thousand
calls a day, the platform makes four thousand — each worker correctly believing it stayed
inside the budget. That is the bug this replaces, and the tests are mostly about the two
properties that fix it: the counter is shared, and the consume is atomic.

Redis is faked with a small object that runs the Lua script's logic. That is a real
limitation and worth stating: it tests the arithmetic and the key layout, not Redis
itself. What it does prove is that two "workers" sharing one store cannot both spend the
last unit, which is the behaviour the script exists for.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "worker" / "src"))

from siembiot_worker.adapters.shared_quota import (  # noqa: E402
    SharedQuotaLedger,
    denied_key,
    read_all,
    used_key,
    window_for,
)


class FakeRedis:
    """One shared store, and an `eval` that applies the script's logic indivisibly.

    Indivisible here because Python is single-threaded through this call — which is
    exactly the guarantee Redis gives the real script, for the same reason.
    """

    def __init__(self) -> None:
        self.store: dict[str, int] = {}

    def eval(self, script: str, numkeys: int, *args: Any) -> list[int]:
        # Dispatched on the script's own key count, the way Redis distinguishes them.
        # The alternative -- assuming every eval is a consume -- is how this fake first
        # failed the refund test it was written to support.
        del script
        if numkeys == 1:
            return [self._refund(*args)]
        return self._consume(*args)

    def _consume(self, *args: Any) -> list[int]:
        used_name, denied_name, limit, units, _ttl = args
        limit, units = int(limit), int(units)
        used = self.store.get(str(used_name), 0)

        if limit >= 0 and used + units > limit:
            self.store[str(denied_name)] = self.store.get(str(denied_name), 0) + units
            return [0, used]

        self.store[str(used_name)] = used + units
        return [1, used + units]

    def _refund(self, *args: Any) -> int:
        used_name, units = args
        remaining = max(0, self.store.get(str(used_name), 0) - int(units))
        self.store[str(used_name)] = remaining
        return remaining

    def get(self, name: str) -> Any:
        value = self.store.get(str(name))
        return None if value is None else str(value).encode()

    def scan_iter(self, match: str) -> Any:
        # Glob, because the real pattern carries two wildcards and a prefix/suffix split
        # silently matches the wrong keys -- which is how this fake first passed a test
        # it should have failed.
        for key in list(self.store):
            if fnmatch(key, match):
                yield key.encode()


def ledger(redis: FakeRedis, limit: int | None = None, adapter: str = "rdap") -> SharedQuotaLedger:
    return SharedQuotaLedger(redis=redis, adapter_id=adapter, limit=limit)


# -- the property the in-memory ledger did not have --------------------------------------


def test_four_workers_are_admitted_exactly_to_the_budget() -> None:
    """The bug in one test, asserted on admission rather than on a final count.

    Four workers, a limit of ten, each trying twenty times: the old in-memory ledger
    would have admitted eighty, because each process counted to ten on its own. A final
    `used == 10` would not have caught that -- every worker's private counter also
    stopped at ten.

    So this counts what was let *through*. Exactly ten calls may proceed, no matter how
    they are distributed, and the eleventh is refused whoever makes it.
    """
    redis = FakeRedis()
    limit = 10
    workers = [ledger(redis, limit=limit, adapter="metered") for _ in range(4)]

    # Interleaved, so no single worker gets a clean run at the budget: this is what
    # concurrent workers actually look like from the counter's point of view.
    admissions = [worker.try_consume() for _ in range(20) for worker in workers]

    assert admissions.count(True) == limit
    # And the admissions come first: once the budget is gone it stays gone, rather than
    # freeing up because some other worker's view drifted.
    assert admissions[:limit] == [True] * limit
    assert set(admissions[limit:]) == {False}


def test_admission_is_shared_not_merely_the_total() -> None:
    """The distinction the previous test rests on, stated separately.

    Four private budgets of ten also produce a total of ten *per worker*. What proves
    they are one budget is that a worker which has personally consumed nothing is still
    refused once the others have spent it.
    """
    redis = FakeRedis()
    spender = ledger(redis, limit=2, adapter="metered")
    bystander = ledger(redis, limit=2, adapter="metered")

    assert spender.try_consume() is True
    assert spender.try_consume() is True

    # This worker has consumed nothing at all, and there is nothing left for it.
    assert bystander.try_consume() is False


def test_the_last_unit_cannot_be_spent_twice() -> None:
    """Atomicity, stated as the thing it prevents.

    A read-then-write ledger would let both workers see one remaining and both take it.
    """
    redis = FakeRedis()
    first, second = ledger(redis, limit=1), ledger(redis, limit=1)

    granted = [first.try_consume(), second.try_consume()]

    assert granted.count(True) == 1


def test_an_unmetered_adapter_is_never_refused() -> None:
    """Every collector shipped today is keyless and unmetered; a limit of None must not
    become a limit of zero."""
    redis = FakeRedis()
    unmetered = ledger(redis, limit=None)

    assert all(unmetered.try_consume() for _ in range(200))
    assert unmetered.remaining is None
    assert unmetered.exhausted is False


# -- refusals are counted ------------------------------------------------------------------


def test_a_refusal_is_recorded_not_only_returned() -> None:
    """`used == limit` cannot distinguish one call turned away from ten thousand. The
    denied counter is the difference between "we reached the budget" and "we have been
    hammering a spent budget all afternoon"."""
    redis = FakeRedis()
    metered = ledger(redis, limit=1)
    metered.try_consume()

    for _ in range(5):
        metered.try_consume()

    assert metered.used == 1
    assert metered.denied == 5


def test_a_refused_call_does_not_consume() -> None:
    redis = FakeRedis()
    metered = ledger(redis, limit=2)

    metered.try_consume()
    metered.try_consume()
    metered.try_consume()

    assert metered.used == 2
    assert metered.remaining == 0


# -- windows -------------------------------------------------------------------------------


def test_the_window_is_a_utc_day() -> None:
    """Carried in the key, so the reset costs nothing: tomorrow's key does not exist yet.

    It also bounds the damage of a stuck counter to a single day.
    """
    assert window_for(datetime(2026, 8, 12, 23, 59, tzinfo=UTC)) == "2026-08-12"
    assert window_for(datetime(2026, 8, 13, 0, 1, tzinfo=UTC)) == "2026-08-13"


def test_yesterdays_spending_does_not_count_against_today() -> None:
    redis = FakeRedis()
    redis.store[used_key("rdap", "2026-08-11")] = 9_999

    assert ledger(redis, limit=5).used == 0
    assert ledger(redis, limit=5).try_consume() is True


def test_adapters_do_not_share_a_counter() -> None:
    redis = FakeRedis()
    first = ledger(redis, limit=1, adapter="rdap")
    second = ledger(redis, limit=1, adapter="certificate_transparency")

    assert first.try_consume() is True
    assert second.try_consume() is True


# -- what the snapshot reads ----------------------------------------------------------------


def test_the_snapshot_finds_every_adapter_that_spent_anything() -> None:
    """Scanned rather than read from a registry: an adapter spending quota without being
    registered anywhere is exactly the one worth seeing."""
    redis = FakeRedis()
    window = window_for()
    redis.store[used_key("rdap", window)] = 7
    redis.store[denied_key("rdap", window)] = 2
    redis.store[used_key("unregistered_adapter", window)] = 3

    readings = {reading.adapter_id: reading for reading in read_all(redis)}

    assert readings["rdap"].used == 7
    assert readings["rdap"].denied == 2
    assert readings["unregistered_adapter"].used == 3


def test_the_snapshot_reads_one_day() -> None:
    redis = FakeRedis()
    redis.store[used_key("rdap", "2026-01-01")] = 5
    redis.store[used_key("rdap", window_for())] = 1

    assert [reading.used for reading in read_all(redis)] == [1]


def test_zero_units_is_refused_rather_than_silently_ignored() -> None:
    """A call that consumed nothing would be a call outside the budget."""
    with pytest.raises(ValueError):
        ledger(FakeRedis(), limit=5).try_consume(0)


# -- the guard holds either ledger -------------------------------------------------------


def test_the_guard_refunds_through_the_interface() -> None:
    """The guard charges quota before asking the rate limiter, so a call the limiter
    turns away has already been paid for.

    It used to give the unit back by writing `quota.used -= 1`, which works on a field
    and not on a counter in Redis. Against the shared ledger that would have drained the
    budget on calls that were never made, invisibly, because nothing failed.
    """
    from siembiot_worker.adapters.contract import RateLimitPolicy
    from siembiot_worker.adapters.resilience import (
        AdapterGuard,
        CircuitBreaker,
        CircuitBreakerPolicy,
        TokenBucketRateLimiter,
    )

    redis = FakeRedis()
    shared = ledger(redis, limit=5, adapter="metered")
    clock = lambda: 0.0  # noqa: E731 - frozen, so the bucket never refills

    # A bucket of one, drained, so the next call is turned away *after* quota is charged.
    limiter = TokenBucketRateLimiter(RateLimitPolicy(1, 1.0, burst=1), clock)
    limiter.try_acquire()

    guard = AdapterGuard(
        rate_limiter=limiter,
        breaker=CircuitBreaker(CircuitBreakerPolicy(), clock),
        quota=shared,
    )

    decision = guard.acquire()

    assert decision.permitted is False
    assert decision.reason_code == "rate_limited"
    assert shared.used == 0, "quota was charged for a call the limiter refused"


def test_a_refund_cannot_drive_the_counter_negative() -> None:
    """A negative budget would present itself as capacity nobody has."""
    redis = FakeRedis()
    shared = ledger(redis, limit=5, adapter="metered")

    shared.refund(3)

    assert shared.used == 0
    assert shared.remaining == 5
