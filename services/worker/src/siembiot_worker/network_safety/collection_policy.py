"""Destination policy for evidence collection.

Every collector destination is derived here from an operation class, never from a
free-form URL supplied by a provider, a redirect target, or agent output.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import quote, urljoin, urlsplit

from siembiot_worker.network_safety.host_policy import HostPolicyError, canonical_host
from siembiot_worker.network_safety.url_policy import (
    VERIFICATION_PATH,
    DestinationPolicyError,
)

MTA_STS_PATH = "/.well-known/mta-sts.txt"
SECURITY_TXT_PATH = "/.well-known/security.txt"
MAX_PATH_BYTES = 512
MAX_QUERY_BYTES = 256
_UNRESERVED_PATH = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~/%:@!$&'()*+,;="
)
_UNRESERVED_QUERY = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~%:@!$&'()*+,;=/?"
)


class OperationClass(StrEnum):
    HTTPS_VERIFICATION = "https_verification"
    HTTP_SURFACE = "http_surface"
    EMAIL_POLICY_FETCH = "email_policy_fetch"
    DNS_QUERY = "dns_query"
    TLS_INSPECTION = "tls_inspection"
    RDAP_QUERY = "rdap_query"
    CT_QUERY = "ct_query"
    #: Opening a TCP connection to a port the target did not advertise. The first
    #: operation in this product that asks a host something rather than reading what
    #: it publishes, which is why it is authorized-only.
    PORT_PROBE = "port_probe"
    #: Asking a third party what they think of the target. Nothing is sent to the
    #: institution at all -- the query goes to a blocklist or threat-intel provider --
    #: so it is passive in the strongest sense available here: the assessed party's
    #: infrastructure is never touched. It is a distinct class rather than a DNS query
    #: because the destination is a provider under a licence, which is a different thing
    #: to reason about than a public protocol.
    REPUTATION_QUERY = "reputation_query"
    #: Connecting to a published MX host on 25 and asking whether it offers STARTTLS.
    #: Passive, by the same test as an HTTP GET: an MX record exists precisely to invite
    #: this connection, and every mail server on the internet accepts that invitation.
    #: Not target-owned -- a domain's mail very often runs on somebody else's host.
    SMTP_STARTTLS = "smtp_starttls"


HTTP_OPERATION_CLASSES = frozenset(
    {
        OperationClass.HTTPS_VERIFICATION,
        OperationClass.HTTP_SURFACE,
        OperationClass.EMAIL_POLICY_FETCH,
        OperationClass.RDAP_QUERY,
        OperationClass.CT_QUERY,
        # Reputation over HTTP. The class predates any provider and was written expecting
        # a DNS blocklist, which is why it was missing here; OTX answers over HTTPS, and
        # a source that speaks HTTP still has to come through the same broker as the rest.
        OperationClass.REPUTATION_QUERY,
    }
)
_TARGET_OWNED_CLASSES = frozenset(
    {
        OperationClass.HTTPS_VERIFICATION,
        OperationClass.HTTP_SURFACE,
        OperationClass.EMAIL_POLICY_FETCH,
        OperationClass.TLS_INSPECTION,
    }
)
_FIXED_PATHS: dict[OperationClass, str] = {
    OperationClass.HTTPS_VERIFICATION: VERIFICATION_PATH,
    OperationClass.EMAIL_POLICY_FETCH: MTA_STS_PATH,
    OperationClass.HTTP_SURFACE: "/",
}


def _validate_path(path: str) -> str:
    if not path.startswith("/"):
        raise DestinationPolicyError("forbidden_path")
    if len(path.encode("utf-8")) > MAX_PATH_BYTES:
        raise DestinationPolicyError("path_too_long")
    if ".." in path or "//" in path or "\\" in path:
        raise DestinationPolicyError("forbidden_path")
    if any(character not in _UNRESERVED_PATH for character in path):
        raise DestinationPolicyError("forbidden_path")
    return path


def _validate_query(query: str) -> str:
    if not query:
        return ""
    if len(query.encode("utf-8")) > MAX_QUERY_BYTES:
        raise DestinationPolicyError("query_too_long")
    if any(character not in _UNRESERVED_QUERY for character in query):
        raise DestinationPolicyError("forbidden_query")
    return query


@dataclass(frozen=True)
class CollectionDestination:
    """An authorized HTTP(S) destination bound to one operation class."""

    operation_class: OperationClass
    scheme: str
    host: str
    port: int
    path: str = "/"
    query: str = ""

    def __post_init__(self) -> None:
        if self.operation_class not in HTTP_OPERATION_CLASSES:
            raise DestinationPolicyError("unsupported_operation_class")
        if self.scheme not in {"http", "https"}:
            raise DestinationPolicyError("unsupported_scheme")
        try:
            canonical_host(self.host)
        except HostPolicyError as exc:
            raise DestinationPolicyError(exc.reason) from exc
        expected_port = 443 if self.scheme == "https" else 80
        if self.port != expected_port:
            raise DestinationPolicyError("forbidden_port")
        fixed = _FIXED_PATHS.get(self.operation_class)
        if fixed is not None and self.operation_class is not OperationClass.HTTP_SURFACE:
            if self.path != fixed:
                raise DestinationPolicyError("forbidden_path")
            if self.query:
                raise DestinationPolicyError("forbidden_query")
        _validate_path(self.path)
        _validate_query(self.query)

    @property
    def host_header(self) -> str:
        return self.host

    @property
    def request_target(self) -> str:
        return f"{self.path}?{self.query}" if self.query else self.path

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}{self.request_target}"


def https_destination(operation_class: OperationClass, host: str) -> CollectionDestination:
    """Build the canonical HTTPS destination for a target-owned operation class."""
    if operation_class not in _FIXED_PATHS:
        raise DestinationPolicyError("unsupported_operation_class")
    return CollectionDestination(operation_class, "https", host, 443, _FIXED_PATHS[operation_class])


def http_destination(operation_class: OperationClass, host: str) -> CollectionDestination:
    """Build the plaintext destination used to observe HTTP-to-HTTPS redirect behaviour."""
    if operation_class is not OperationClass.HTTP_SURFACE:
        raise DestinationPolicyError("unsupported_operation_class")
    return CollectionDestination(operation_class, "http", host, 80, "/")


def provider_destination(
    operation_class: OperationClass, host: str, path: str, query: str = ""
) -> CollectionDestination:
    """Build a destination on a configured provider endpoint (RDAP, CT, reputation)."""
    if operation_class not in {
        OperationClass.RDAP_QUERY,
        OperationClass.CT_QUERY,
        OperationClass.REPUTATION_QUERY,
    }:
        raise DestinationPolicyError("unsupported_operation_class")
    return CollectionDestination(operation_class, "https", host, 443, path, query)


def encode_path_segment(value: str) -> str:
    return quote(value, safe="")


def authorize_collection_redirect(
    current: CollectionDestination,
    location: str,
    *,
    authorized_hosts: frozenset[str],
) -> CollectionDestination:
    """Re-authorize a redirect target against the same operation-class policy."""
    parsed = urlsplit(urljoin(current.url, location))
    if parsed.username is not None or parsed.password is not None:
        raise DestinationPolicyError("credentials")
    if parsed.fragment:
        raise DestinationPolicyError("fragment")
    if parsed.scheme not in {"http", "https"}:
        raise DestinationPolicyError("unsupported_scheme")
    if current.scheme == "https" and parsed.scheme == "http":
        raise DestinationPolicyError("tls_downgrade")
    if any(character.isupper() for character in parsed.netloc):
        raise DestinationPolicyError("noncanonical_host")
    host = parsed.hostname
    if host is None:
        raise DestinationPolicyError("noncanonical_host")
    try:
        resolved_host = canonical_host(host)
    except HostPolicyError as exc:
        raise DestinationPolicyError(exc.reason) from exc
    try:
        port = parsed.port
    except ValueError as exc:
        raise DestinationPolicyError("forbidden_port") from exc
    expected_port = 443 if parsed.scheme == "https" else 80
    if port not in {None, expected_port}:
        raise DestinationPolicyError("forbidden_port")
    if not redirect_target_permitted(current.operation_class, resolved_host, authorized_hosts):
        raise DestinationPolicyError("redirect_not_authorized")
    fixed = _FIXED_PATHS.get(current.operation_class)
    if fixed is not None and current.operation_class is not OperationClass.HTTP_SURFACE:
        if parsed.path != fixed or parsed.query:
            raise DestinationPolicyError("forbidden_path")
    return CollectionDestination(
        current.operation_class,
        parsed.scheme,
        resolved_host,
        expected_port,
        _validate_path(parsed.path or "/"),
        _validate_query(parsed.query),
    )


#: Classes whose protocol inherently redirects to a host that cannot be known in
#: advance. RDAP bootstrap answers with a redirect to the authoritative registry, and
#: there are hundreds of registries, so an allowlist is not maintainable.
#:
#: These classes never target a customer domain, their responses are parsed as hostile
#: input under strict size caps, and every other control still applies -- the resolved
#: address must pass the same policy, so a redirect can never reach a private, loopback
#: or metadata address. Only the "must be an already-authorized host" rule is relaxed.
PROVIDER_REDIRECT_CLASSES = frozenset({OperationClass.RDAP_QUERY, OperationClass.CT_QUERY})


def follows_provider_redirects(operation_class: OperationClass) -> bool:
    return operation_class in PROVIDER_REDIRECT_CLASSES


#: Classes that may follow a redirect deeper into the host they were already pointed at.
#:
#: Observing the HTTP surface means observing what a browser would see, and apex-to-www
#: is the single most common configuration on the web. Refusing it does not make the
#: platform safer -- it makes it unable to look at most real sites, which then report as
#: unreachable and score as insufficient evidence.
SAME_SITE_REDIRECT_CLASSES = frozenset({OperationClass.HTTP_SURFACE})

#: Classes whose answer is entirely in the response headers.
#:
#: The HTTP surface checks read the status line, the redirect chain, the security
#: headers and the cookies. None of them reads the page. Fetching it anyway meant that
#: any site whose home page exceeded the body budget was discarded in full -- headers
#: included -- and reported as unreachable, which is how tarom.ro, a site that answers
#: in under a second, came back as a site nobody could reach.
#:
#: Not reading it is also the safer choice, not a relaxation of one: fewer bytes cross
#: the boundary, and the bound that was protecting us is not the one we are removing.
_HEADER_ONLY_CLASSES = frozenset({OperationClass.HTTP_SURFACE})


def body_required(operation_class: OperationClass) -> bool:
    """Whether this class needs the response body to answer its question.

    True for everything that parses content -- a certificate transparency page, an
    MTA-STS policy, a challenge file. False only where the headers are the whole answer.
    """
    return operation_class not in _HEADER_ONLY_CLASSES


def _is_descendant_host(host: str, ancestor: str) -> bool:
    """Whether `host` sits under `ancestor` in the DNS tree.

    The leading dot is what makes this a label-boundary test rather than a string
    prefix test: without it `evil-anaf.ro` would count as living under `anaf.ro`.

    Descendants only, never ancestors. Walking *up* is not safe without consulting the
    public suffix list -- the parent of `victim.github.io` is `github.io`, which belongs
    to somebody else entirely.
    """
    return host.endswith(f".{ancestor}")


def redirect_target_permitted(
    operation_class: OperationClass, host: str, authorized_hosts: frozenset[str]
) -> bool:
    """Whether a redirect may be followed to this host.

    Relaxes only the "must already be an authorized host" rule, and only downward
    within a host the run was already aimed at. Every other control is untouched: the
    resolved address must still pass the address policy on every hop, so a redirect can
    never reach a private, loopback or metadata address; the scheme cannot downgrade;
    the port must be the standard one; and the hop count is capped.
    """
    if host in authorized_hosts:
        return True
    if follows_provider_redirects(operation_class):
        return True
    if operation_class not in SAME_SITE_REDIRECT_CLASSES:
        return False
    return any(_is_descendant_host(host, authorized) for authorized in authorized_hosts)


def is_target_owned(operation_class: OperationClass) -> bool:
    """Target-owned classes require a current authorization for the host itself."""
    return operation_class in _TARGET_OWNED_CLASSES
