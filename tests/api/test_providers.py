"""The provider list an institution is entitled to see.

Most of what it says is reassuring, and that is exactly why it has to be generated rather
than written: a reassuring page maintained by hand becomes a reassuring page that is
wrong, and nobody notices because it still reads well.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "api" / "src"))

from siembiot.providers import _descriptors  # noqa: E402


def test_every_shipped_collector_is_listed() -> None:
    """Nine collectors run; nine providers are disclosed.

    Counted against the collectors rather than against a fixed number, so adding a
    collector without disclosing it fails here instead of shipping quietly.
    """
    collectors = Path(__file__).resolve().parents[2] / "services" / "worker" / "src"
    declared = sum(
        1
        for path in (collectors / "siembiot_worker" / "collectors").glob("*.py")
        if "AdapterDescriptor(" in path.read_text(encoding="utf-8")
    )

    assert len(_descriptors()) == declared


def test_the_list_is_generated_from_what_the_collectors_run() -> None:
    """Each entry carries the adapter's own identifier, so a provider cannot be named
    here that the platform does not actually use."""
    identifiers = {provider.adapter_id for provider in _descriptors()}

    assert "dns_resilience" in identifiers
    assert "certificate_transparency" in identifiers
    assert all(identifier.strip() for identifier in identifiers)


def test_no_shipped_provider_needs_a_credential() -> None:
    """The claim the README makes and this page displays.

    Asserted rather than trusted: the moment a collector needs a key, the platform stops
    being runnable without paid accounts and a public body's data starts reaching a
    commercial service. That should fail a test, not be discovered on the page.
    """
    needing = [provider.adapter_id for provider in _descriptors() if provider.required_secrets]

    assert needing == [], f"{needing} now require credentials; the disclosure must say so"


def test_every_provider_explains_its_terms() -> None:
    """A row saying only "we contact this service" tells an institution nothing about
    what that service is entitled to do with the request."""
    for provider in _descriptors():
        assert provider.terms_notes.strip(), provider.adapter_id


def test_the_authorized_only_collector_is_marked_as_such() -> None:
    """Port probing is the one thing here that asks a host a question rather than
    reading what it published, and the page must not present it as equivalent."""
    ports = next(p for p in _descriptors() if p.adapter_id == "port_surface")

    assert ports.passive is False


def test_the_passive_flag_agrees_with_the_adapter_group() -> None:
    """Two representations of the same fact, kept in step.

    `AdapterGroup.ACTIVE_PROBE` and `passive=False` say the same thing, and they
    disagreed: every descriptor inherited `passive=True` because nothing ever read it.
    A flag nobody reads is a flag that is wrong, and this one was about to be published
    to the institutions being probed.
    """
    from siembiot_worker.adapters.contract import AdapterGroup

    for provider in _descriptors():
        is_active_group = provider.group == AdapterGroup.ACTIVE_PROBE.value
        assert provider.passive is not is_active_group, provider.adapter_id
