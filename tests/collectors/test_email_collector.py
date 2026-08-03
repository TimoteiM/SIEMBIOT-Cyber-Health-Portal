from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from siembiot_worker.collection.broker import FixtureBrokerResult, FixtureInternetBroker
from siembiot_worker.collection.fixtures import FixtureScenarioPack
from siembiot_worker.collection.models import ObservationOutcome
from siembiot_worker.collectors.common import DNSBroker, FixtureCollectorContext
from siembiot_worker.collectors.email.collector import EmailDNSCollector

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "fake_internet" / "v1"


class RecordingBroker:
    def __init__(self, delegate: DNSBroker) -> None:
        self.delegate = delegate
        self.dns_requests: list[tuple[str, str]] = []

    def resolve_dns(
        self,
        scenario_id: str,
        host: str,
        record_type: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> FixtureBrokerResult:
        self.dns_requests.append((host, record_type))
        return self.delegate.resolve_dns(
            scenario_id, host, record_type, cancelled=cancelled
        )


def _components() -> tuple[FixtureScenarioPack, FixtureCollectorContext]:
    pack = FixtureScenarioPack.load(FIXTURE_ROOT)
    scenario = pack.scenario("healthy")
    return pack, FixtureCollectorContext(
        scope_reference="scope-example-test",
        scenario_id=scenario.id,
        scenario_sha256=scenario.digest,
    )


def test_email_collector_covers_fixture_mail_dns_controls() -> None:
    pack, context = _components()
    observations = EmailDNSCollector(FixtureInternetBroker(pack)).collect(
        context,
        "example.test",
        dkim_selectors=("selector1",),
    )
    by_check = {item.payload["check"]: item for item in observations}
    assert set(by_check) == {
        "mx",
        "spf",
        "dmarc",
        "mta_sts",
        "tls_rpt",
        "tlsa",
        "bimi",
        "dkim:selector1",
    }
    assert all(item.outcome is ObservationOutcome.PASS for item in observations)
    assert all(item.payload["fixture_only"] is True for item in observations)


def test_dkim_uses_only_explicit_signed_input_selectors() -> None:
    pack, context = _components()
    broker = RecordingBroker(FixtureInternetBroker(pack))
    EmailDNSCollector(broker).collect(context, "example.test", dkim_selectors=("selector1",))
    requested_dkim = [host for host, _ in broker.dns_requests if "._domainkey." in host]
    assert requested_dkim == ["selector1._domainkey.example.test"]


def test_no_dkim_lookup_occurs_without_declared_selectors() -> None:
    pack, context = _components()
    broker = RecordingBroker(FixtureInternetBroker(pack))
    EmailDNSCollector(broker).collect(context, "example.test", dkim_selectors=())
    assert all("._domainkey." not in host for host, _ in broker.dns_requests)
