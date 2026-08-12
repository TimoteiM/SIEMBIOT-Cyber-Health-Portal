"""The infrastructure gate, and whether it can fail.

The real compose file passes. That is the least interesting fact in this file, and on its
own it is worth nothing: a checker that reads nothing reports no problems, which looks
exactly like a hardened stack.

So most of what follows feeds each rule a document that violates it and asserts a
complaint comes back. A rule with no failing case here has never been shown to be a rule.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from check_infrastructure import (  # noqa: E402
    PRODUCTION_LIKE,
    check_hardening,
    check_images_are_pinned,
    check_interpolation_fails_closed,
    check_nothing_reaches_the_host,
    check_referenced_variables_are_documented,
    check_the_database_is_not_published,
    check_the_parse_found_something,
    load,
    run,
    services,
)

HARDENED: dict[str, Any] = {
    "read_only": True,
    "security_opt": ["no-new-privileges:true"],
    "cap_drop": ["ALL"],
}


def stack(**overrides: dict[str, Any]) -> dict[str, Any]:
    """A document that passes, so a test can break exactly one thing."""
    base = {name: dict(HARDENED) for name in ("api", "worker", "beat", "web")} | {
        "postgres": {},
        "redis": {},
    }
    return {"services": base | overrides}


# -- the real file ------------------------------------------------------------------------


def test_the_stack_as_committed_is_clean() -> None:
    assert run() == []


def test_the_hardening_is_read_through_the_yaml_anchor() -> None:
    """The bug this gate was most likely to have.

    The compose file does not write `read_only` under each service -- it merges an
    anchor, `<<: *hardening`. A parser that did not resolve merge keys would find no
    hardening at all, and the two possible outcomes are both wrong in ways that look
    right: every service reported as unhardened (noisy, gets the gate deleted), or the
    document reported as empty (silent, passes forever).

    So this asserts both halves: the anchor is genuinely what the file uses, and the
    parsed result genuinely has the value.
    """
    raw = PRODUCTION_LIKE.read_text(encoding="utf-8")
    assert "<<: *hardening" in raw, "the file no longer uses an anchor; this test is stale"

    parsed = services(load(PRODUCTION_LIKE))

    assert parsed["api"]["read_only"] is True
    assert "no-new-privileges:true" in parsed["api"]["security_opt"]


# -- the guard that makes the rest mean anything ------------------------------------------


def test_an_empty_document_is_a_failure_rather_than_a_pass() -> None:
    """The whole point.

    A checker that finds nothing to check must say so. This is the difference between
    "the stack is hardened" and "I did not look".
    """
    problems = check_the_parse_found_something({}, "empty.yml")

    assert problems
    assert "not reading the file it thinks it is" in problems[0]


def test_a_stack_missing_one_service_is_a_failure() -> None:
    """A rename would otherwise silently remove that service from every rule below."""
    document = stack()
    del document["services"]["worker"]

    assert check_the_parse_found_something(document, "renamed.yml")


def test_run_reports_the_parse_failure_and_nothing_else() -> None:
    """Short-circuited on purpose. Twelve complaints about missing hardening would bury
    the one that says the file was never read."""
    import check_infrastructure

    original = check_infrastructure.EXPECTED_SERVICES
    try:
        check_infrastructure.EXPECTED_SERVICES = frozenset({"a-service-that-is-not-there"})
        problems = run()
    finally:
        check_infrastructure.EXPECTED_SERVICES = original

    assert len(problems) == 1
    assert "were not found" in problems[0]


# -- each rule, shown failing -------------------------------------------------------------


def test_a_writable_root_filesystem_is_caught() -> None:
    problems = check_hardening(stack(api=dict(HARDENED) | {"read_only": False}), "f.yml")

    assert any("read_only" in problem for problem in problems)


def test_a_missing_read_only_key_is_caught_as_well_as_a_false_one() -> None:
    """Absent and `false` are the same risk. A truthiness check would catch one of them."""
    spec = dict(HARDENED)
    del spec["read_only"]

    assert any("read_only" in problem for problem in check_hardening(stack(api=spec), "f.yml"))


def test_missing_no_new_privileges_is_caught() -> None:
    problems = check_hardening(stack(api=dict(HARDENED) | {"security_opt": []}), "f.yml")

    assert any("no-new-privileges" in problem for problem in problems)


def test_undropped_capabilities_are_caught() -> None:
    problems = check_hardening(stack(worker=dict(HARDENED) | {"cap_drop": ["NET_RAW"]}), "f.yml")

    assert any("capabilities are not dropped" in problem for problem in problems)


def test_added_capabilities_are_caught() -> None:
    """`cap_drop: [ALL]` followed by `cap_add: [SYS_ADMIN]` reads as hardened and is not."""
    problems = check_hardening(stack(worker=dict(HARDENED) | {"cap_add": ["SYS_ADMIN"]}), "f.yml")

    assert any("adds capabilities" in problem for problem in problems)


def test_a_privileged_container_is_caught() -> None:
    problems = check_nothing_reaches_the_host(stack(api={"privileged": True}), "f.yml")

    assert any("privileged" in problem for problem in problems)


def test_a_mounted_docker_socket_is_caught() -> None:
    """Root on the host with extra steps, and the single most common thing to find in a
    compose file that was written quickly."""
    document = stack(api={"volumes": ["/var/run/docker.sock:/var/run/docker.sock:ro"]})

    problems = check_nothing_reaches_the_host(document, "f.yml")

    assert any("docker socket" in problem for problem in problems)


def test_a_docker_socket_in_long_form_is_caught_too() -> None:
    """The same mount written the other way. A rule that only understands one syntax is
    a rule with a documented bypass."""
    document = stack(
        api={"volumes": [{"type": "bind", "source": "/run/docker.sock", "target": "/x"}]}
    )

    problems = check_nothing_reaches_the_host(document, "f.yml")

    assert any("docker socket" in problem for problem in problems)


def test_host_networking_is_caught() -> None:
    problems = check_nothing_reaches_the_host(stack(worker={"network_mode": "host"}), "f.yml")

    assert any("host networking" in problem for problem in problems)


def test_a_published_database_port_is_caught() -> None:
    document = stack(postgres={"ports": ["5432:5432"]})

    problems = check_the_database_is_not_published(document, "f.yml")

    assert any("publishes" in problem for problem in problems)


def test_an_unpinned_image_is_caught() -> None:
    problems = check_images_are_pinned(stack(redis={"image": "redis:7"}), "f.yml")

    assert any("not pinned by digest" in problem for problem in problems)


def test_a_service_built_from_a_dockerfile_is_not_asked_to_pin_a_tag() -> None:
    """Its base is pinned by the Dockerfile gate. Checking the same property twice in two
    vocabularies means one of them goes stale without anybody noticing."""
    document = stack(api=dict(HARDENED) | {"image": "siembiot/api:dev", "build": {"context": "."}})

    assert check_images_are_pinned(document, "f.yml") == []


# -- the parser itself ---------------------------------------------------------------------


def test_a_file_that_is_not_a_mapping_raises_rather_than_returning_empty() -> None:
    """Returning `{}` here would flow straight into "no problems found"."""
    import pytest

    path = ROOT / "pyproject.toml"  # valid YAML-ish, not a compose mapping
    del path

    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False, encoding="utf-8") as handle:
        handle.write("- just\n- a\n- list\n")
        written = Path(handle.name)

    try:
        with pytest.raises(ValueError):
            load(written)
    finally:
        written.unlink()


def test_every_compose_file_in_the_repository_parses() -> None:
    """A file this gate cannot read is a file this gate is not checking."""
    files = sorted((ROOT / "infra" / "compose").glob("*.compose.yml"))

    assert files, "no compose files found; the gate is looking in the wrong place"
    for path in files:
        assert isinstance(yaml.safe_load(path.read_text(encoding="utf-8")), dict), path.name


# -- variable interpolation ----------------------------------------------------------------


def test_a_variable_bare_everywhere_is_caught() -> None:
    """The rule as it was actually needed. `SIEMBIOT_POSTGRES_RETENTION_PASSWORD` was
    interpolated bare in the one place it appeared, so an unset value would have brought
    a database role up with an empty password and a warning nobody reads."""
    raw = "url: postgresql://role:${SOME_PASSWORD}@host/db"

    problems = check_interpolation_fails_closed(raw, "f.yml")

    assert any("SOME_PASSWORD" in problem for problem in problems)


def test_a_variable_required_once_is_not_flagged_where_it_is_bare() -> None:
    """The accuracy that keeps this rule usable.

    Compose evaluates every interpolation, so one `:?` anywhere stops the stack and the
    same variable written bare in six connection strings afterwards is harmless. Flagging
    each bare use would report six problems where there are none, and a checker that
    cries wolf gets deleted.
    """
    raw = """
    postgres:
      environment:
        POSTGRES_PASSWORD: ${SOME_PASSWORD:?set in local .env}
    api:
      environment:
        URL: postgresql://role:${SOME_PASSWORD}@host/db
        OTHER: postgresql://role:${SOME_PASSWORD}@host/other
    """

    assert check_interpolation_fails_closed(raw, "f.yml") == []


def test_a_shell_escape_is_not_mistaken_for_an_interpolation() -> None:
    """`$${VAR}` is compose's escape for passing a literal `${VAR}` to a shell. Every
    healthcheck in the real file uses it, and flagging them would have buried the one
    genuine finding under six false ones."""
    raw = 'test: ["CMD-SHELL", "pg_isready -d $${POSTGRES_DB}"]'

    assert check_interpolation_fails_closed(raw, "f.yml") == []


def test_an_undocumented_required_variable_is_caught() -> None:
    """`.env` is untracked, so the example file is the only record an operator has that
    a setting exists at all."""
    raw = "environment:\n  X: ${A_VARIABLE_NOBODY_DOCUMENTED:?required}"

    problems = check_referenced_variables_are_documented(raw, "f.yml")

    assert any("A_VARIABLE_NOBODY_DOCUMENTED" in problem for problem in problems)


def test_a_variable_with_a_default_need_not_be_documented() -> None:
    """It works without being set, so an operator who never learns of it is not stuck."""
    raw = "environment:\n  X: ${SOMETHING_OPTIONAL:-a-sensible-default}"

    assert check_referenced_variables_are_documented(raw, "f.yml") == []


# -- the port and the origin have to agree -------------------------------------------------


def test_the_documented_origin_matches_the_documented_web_port() -> None:
    """A mismatch here is a 403 on every write, and nothing says why.

    `SIEMBIOT_PUBLIC_BASE_URL` is the exact string the API compares the `Origin` header
    against for any state change. `SIEMBIOT_WEB_PORT` is where the browser actually
    reaches the interface. Move one without the other -- which is the obvious thing to do
    when 3000 is already taken -- and every read still works while every write fails with
    `origin_rejected`, which reads as a bug in the application rather than as one line of
    configuration.

    Checked against `.env.example` and the compose default, because those are the two
    tracked places a value can drift; `.env` is untracked and cannot be asserted on.
    """
    import re

    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    compose = PRODUCTION_LIKE.read_text(encoding="utf-8")

    base_url = re.search(r"(?m)^SIEMBIOT_PUBLIC_BASE_URL=(\S+)$", example)
    documented_port = re.search(r"(?m)^SIEMBIOT_WEB_PORT=(\d+)$", example)
    compose_default = re.search(r"SIEMBIOT_WEB_PORT:-(\d+)", compose)

    assert base_url and documented_port and compose_default, "a setting went missing"

    origin_port = re.search(r":(\d+)/?$", base_url.group(1))
    assert origin_port, f"no port in {base_url.group(1)}"

    assert origin_port.group(1) == documented_port.group(1) == compose_default.group(1), (
        f"origin says :{origin_port.group(1)}, SIEMBIOT_WEB_PORT says "
        f"{documented_port.group(1)}, compose defaults to {compose_default.group(1)}. "
        "A write from the browser will be refused as origin_rejected."
    )


def test_the_documented_origin_names_a_scheme() -> None:
    """The half of the port/origin coupling that the first version of these tests missed.

    `SIEMBIOT_PUBLIC_BASE_URL` is compared to the `Origin` header as a whole string, so
    `http://localhost:3100` and `https://localhost:3100` are different origins even
    though the port agrees. That mismatch was made for real within an hour of the
    port check being written: the development server runs `--experimental-https` while
    the production-like stack has no TLS termination and serves plain HTTP, so a value
    correct for one is wrong for the other, and the symptom is identical -- every read
    works, every write is refused.

    A test cannot pick the scheme, because the two stacks genuinely differ. What it can
    do is insist the value carries one at all, so nobody writes a bare `localhost:3100`
    and gets a refusal with no scheme to compare.
    """
    import re

    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    value = re.search(r"(?m)^SIEMBIOT_PUBLIC_BASE_URL=(\S+)$", example)

    assert value, "SIEMBIOT_PUBLIC_BASE_URL is not documented"
    assert value.group(1).startswith(("http://", "https://")), (
        f"{value.group(1)!r} has no scheme. It is compared to the Origin header as a "
        "whole string, and a value without a scheme can never match one."
    )


def test_an_origin_refusal_says_why_somewhere() -> None:
    """A 403 that explains nothing anywhere turns a one-line misconfiguration into an
    afternoon. The response stays uninformative on purpose -- naming the accepted origin
    tells an attacker what to forge -- so the explanation has to be server-side.
    """
    auth = (ROOT / "services" / "api" / "src" / "siembiot" / "auth.py").read_text(encoding="utf-8")

    assert "origin rejected: expected" in auth, (
        "the origin check refuses without recording what it expected"
    )
    assert "SIEMBIOT_PUBLIC_BASE_URL" in auth, "the log does not name the setting that fixes it"
