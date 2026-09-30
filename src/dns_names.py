"""Offline DNS-name semantics shared by state grouping and DGA inference."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import tldextract


_PSL = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    fallback_to_snapshot=True,
    include_psl_private_domains=True,
)


@dataclass(frozen=True, slots=True)
class DGAEligibleName:
    normalized_query: str
    registrable_domain: str
    public_suffix: str


def normalize_dns_name(value: str) -> str:
    return value.strip().rstrip(".").lower()


def dga_eligible_name(value: str) -> DGAEligibleName | None:
    """Return public-DNS identity, or None when DGA inference is meaningless.

    This deliberately affects only per-query DGA ML. DNS state continues to
    retain every valid observation, including LAN and discovery namespaces.
    """

    normalized = normalize_dns_name(value)
    if not normalized or "." not in normalized or any(not part for part in normalized.split(".")):
        return None
    unbracketed = normalized[1:-1] if normalized.startswith("[") and normalized.endswith("]") else normalized
    try:
        ipaddress.ip_address(unbracketed)
        return None
    except ValueError:
        pass
    if normalized == "localhost" or normalized.endswith((
        ".localhost", ".local", ".in-addr.arpa", ".ip6.arpa",
    )):
        return None
    extracted = _PSL(normalized)
    suffix = extracted.suffix.lower()
    domain = extracted.domain.lower()
    if not suffix or not domain:
        return None
    return DGAEligibleName(normalized, f"{domain}.{suffix}", suffix)


def registrable_domain_parts(value: str) -> tuple[str, str]:
    """Return the existing DNS-state grouping semantics using the offline PSL."""

    normalized = normalize_dns_name(value)
    extracted = _PSL(normalized)
    registrable = extracted.top_domain_under_public_suffix
    if not registrable:
        registrable = extracted.domain or normalized
    return registrable.lower(), extracted.subdomain.lower()
