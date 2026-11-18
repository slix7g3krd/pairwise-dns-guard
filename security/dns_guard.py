"""SSRF / DNS-rebinding guards for the image fetcher.

The image fetcher accepts a user-supplied URL.  Every step below is
deliberately fail-closed: anything we cannot positively prove to be a
public address is treated as unsafe.

Key invariants
--------------
* ``normalize_ip`` is the single canonicalisation point.  Every other
  helper funnels input through it, so decimal/octal/hex/short-form
  literals and IPv4-mapped IPv6 addresses cannot slip past a dotted-quad
  check.
* The IP that is validated is the IP that is connected to
  (``pin_connection``), and the cache is keyed on the exact
  ``(host, ip)`` pair so a cached verdict can never be reused for a
  different name or a different address.
* Every answer in a DNS response must pass (``all_answers_public``);
  taking only the first answer is a classic rebinding bypass.
* Redirects are re-validated per hop
  (``redirect_target_ok`` is the per-hop check), and proxies are not a
  substitute for validation.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


# Ranges that ``ipaddress`` does *not* classify as private but which must
# never be reachable from a public-facing fetcher: CGNAT, benchmarking,
# documentation, multicast, reserved and "this network" space.
_EXTRA_BLOCKED_V4 = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",        # "this network"
        "100.64.0.0/10",    # carrier-grade NAT
        "192.0.0.0/24",     # IETF protocol assignments
        "192.0.2.0/24",     # TEST-NET-1
        "198.18.0.0/15",    # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",   # TEST-NET-3
        "224.0.0.0/4",      # multicast
        "240.0.0.0/4",      # reserved + broadcast
    )
)

_EXTRA_BLOCKED_V6 = tuple(
    ipaddress.ip_network(n)
    for n in (
        "::/128",           # unspecified
        "::1/128",          # loopback
        "64:ff9b::/96",     # NAT64 (can embed private IPv4)
        "2001:db8::/32",    # documentation
        "fec0::/10",        # deprecated site-local (is_global still True)
        "ff00::/8",         # multicast
    )
)

# Hostnames that resolve locally / are commonly used for rebinding.
_LOCAL_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
    }
)
_LOCAL_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".home.arpa",
)
_LOCAL_EXACT_IPS = frozenset({"169.254.169.254"})

_ALLOWED_SCHEMES = frozenset({"http", "https"})


def _clean(value: object) -> str | None:
    """Return a stripped string, or ``None`` for non-str/empty input."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _is_numeric_obfuscation(host: str) -> bool:
    """Detect hostnames that are really non-standard IPv4 literals.

    ``inet_aton`` accepts ``0177.0.0.1`` (octal), ``0x7f000001`` (hex),
    ``2130706433`` (decimal) and ``127.1`` (short form).  A plain DNS name
    never consists exclusively of digits, dots, ``x``/``X`` and hex
    letters *without* a real TLD, so rejecting hosts whose labels are all
    numeric-ish closes the wording gap between ``ipaddress`` and the
    resolver.
    """
    lowered = host.lower()
    if lowered.startswith("0x") or lowered.startswith("+"):
        return True
    # Strip a single trailing dot used to denote a FQDN.
    if lowered.endswith("."):
        lowered = lowered[:-1]
    labels = lowered.split(".")
    if not labels:
        return True
    return all(
        label == ""
        or label.isdigit()
        or (label.startswith("0x") and all(c in "0123456789abcdef" for c in label[2:]))
        for label in labels
    )


def normalize_ip(value: object) -> str | None:
    """Canonicalise an IP literal, or return ``None`` if unusable.

    * Accepts IPv4 and IPv6, including bracketed IPv6 and zone indices.
    * IPv4-mapped IPv6 (``::ffff:127.0.0.1``) is unwrapped to the embedded
      IPv4 address so it is checked against the IPv4 rules.
    * Non-standard literals (octal ``0177.0.0.1``, decimal, hex, short
      dotted forms) are *rejected* rather than silently interpreted, so
      they can never mean different things to the validator and the
      connector.
    """
    text = _clean(value)
    if text is None:
        return None

    # Bracketed IPv6 literal, e.g. "[::1]" or "[::1]:8080".
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return None
        text = text[1:end]
    elif text.count(":") == 1 and "." in text:
        # "127.0.0.1:80" is not an IP literal.
        return None

    # Drop a zone index ("fe80::1%eth0").
    if "%" in text:
        text = text.split("%", 1)[0]

    # Only the canonical dotted-quad form is accepted for IPv4.  Octal
    # ("0177.0.0.1"), decimal ("2130706433"), hex ("0x7f000001") and
    # short ("127.1") literals are rejected rather than reinterpreted:
    # a literal must never mean one thing to the validator and another to
    # the connector.  ``ipaddress`` enforces this, including rejecting
    # leading zeros, but we keep the check explicit here.
    if "." in text and ":" not in text:
        labels = text.split(".")
        if len(labels) != 4 or not all(
            label.isdigit() and (label == "0" or not label.startswith("0"))
            for label in labels
        ):
            return None

    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None

    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    return str(addr)


def is_private_ip(value: object) -> bool:
    """Return ``True`` unless ``value`` is a positively identified public IP.

    Fail-closed: unparseable input counts as private.  Loopback, RFC1918,
    link-local, CGNAT, multicast, documentation and reserved ranges are
    all rejected, as are IPv6 unique-local and link-local addresses.
    """
    normalized = normalize_ip(value)
    if normalized is None:
        return True

    try:
        addr = ipaddress.ip_address(normalized)
    except ValueError:
        return True

    if normalized in _LOCAL_EXACT_IPS:
        return True

    if isinstance(addr, ipaddress.IPv4Address):
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return True
        if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
            return True
        if any(addr in net for net in _EXTRA_BLOCKED_V4):
            return True
        # Anything not globally routable is not a public destination.
        return not addr.is_global

    if isinstance(addr, ipaddress.IPv6Address):
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return True
        if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
            return True
        if any(addr in net for net in _EXTRA_BLOCKED_V6):
            return True
        return not addr.is_global

    return True


def all_answers_public(answers: object) -> bool:
    """Validate *every* address in a DNS response.

    A response is only safe when it is non-empty and every single answer
    (A and AAAA alike, however many there are) normalises to a public
    address.  An attacker controlling one record must not be able to hide
    an internal address behind a public answer that we happen to pick
    first.
    """
    if isinstance(answers, (str, bytes)) or answers is None:
        return False
    try:
        items = list(answers)  # type: ignore[arg-type]
    except TypeError:
        return False

    if not items:
        return False

    for answer in items:
        if not isinstance(answer, str):
            return False
        if is_private_ip(answer):
            return False
    return True


def pin_connection(vetted_ip: object, connect_ip: object) -> bool:
    """Ensure the address we connect to is exactly the one we validated.

    DNS must not be consulted again between validation and connection:
    the resolver result is pinned and reused for the lifetime of the
    entry (the TTL window), so a rebinding answer that arrives later can
    never reach the socket.  Private/unparseable addresses on either side
    fail closed.
    """
    vetted = normalize_ip(vetted_ip)
    connected = normalize_ip(connect_ip)
    if vetted is None or connected is None:
        return False
    if is_private_ip(vetted) or is_private_ip(connected):
        return False
    return vetted == connected


def redirect_target_ok(url: object) -> bool:
    """Validate a single redirect target (called once per hop).

    A 302 is not a licence to skip validation: the new location gets the
    same checks as the original URL.  Empty hosts, non-HTTP(S) schemes,
    credentials tricks, loopback/localhost names and IP literals in any
    notation are rejected.  Proxies are never used to "explain away" a
    failure here -- proxy fallback is disabled in the fetcher.
    """
    text = _clean(url)
    if text is None:
        return False
    if any(ch in text for ch in ("\\", "\x00", "\r", "\n")):
        return False

    try:
        parts = urlsplit(text)
    except ValueError:
        return False

    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        return False

    # netloc must exist; otherwise urlsplit happily yields an empty host
    # and the request would fall back to the local machine.
    if not parts.netloc:
        return False

    try:
        host = parts.hostname
        _ = parts.port  # force port validation (raises on garbage)
    except ValueError:
        return False

    if host is None:
        return False
    host = host.strip().rstrip(".")
    if not host:
        return False

    # Whitespace/control characters are never valid in a host and are a
    # common parser-differential trick.
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in host):
        return False

    lowered = host.lower()
    if lowered in _LOCAL_HOSTNAMES or lowered.endswith(_LOCAL_SUFFIXES):
        return False

    # Reject userinfo tricks such as "public.example@127.0.0.1": URLs are
    # allowed to carry credentials, but for a bare redirect target they
    # are far more often an obfuscation attempt.
    if "@" in parts.netloc:
        return False

    normalized = normalize_ip(host)
    if normalized is not None:
        return not is_private_ip(normalized)

    # Not a valid IP literal.  If it looks like a mangled one (decimal,
    # octal, hex, short form), refuse rather than hand it to the resolver.
    if _is_numeric_obfuscation(host):
        return False

    # A bare single-label host is resolved through local search domains
    # and can point at the host itself.
    if "." not in host:
        return False

    return True


def cache_key(host: object, ip: object) -> str:
    """Build a cache key binding the resolved address to its hostname.

    The key includes the normalised host, so a cached "public" verdict for
    ``evil.example`` can never be served for ``internal.example`` that
    happens to share an IP, nor can a cached IP be reused after the name
    is rebound.  Keys are exact ``(host, ip)`` pairs; callers additionally
    honour the record TTL and re-pin the connection.
    """
    host_text = _clean(host)
    ip_text = normalize_ip(ip)
    if host_text is None or ip_text is None:
        raise ValueError("cache_key requires a host and a valid IP")

    host_norm = host_text.lower().rstrip(".")
    if not host_norm:
        raise ValueError("cache_key requires a non-empty host")

    return f"{host_norm}|{ip_text}"
