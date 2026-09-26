"""Deterministic intelligence matcher (pure string ops, offline only).

URL rules:
- hostname is lowercased, trailing dots stripped, IDNA-encoded.
- ``hostname`` indicators match that exact host only.
- ``domain`` indicators match the exact host or its registrable domain
  (naive last-two-labels; documented limitation for multi-level TLDs).
- Matching is always exact-label based: ``notevil.example`` never matches
  ``evil.example`` because the registrable domains differ.

UPI rules:
- the payee address is lowercased and matched exactly against
  ``upi_handle`` indicators. Malformed input simply does not match.

This module never fetches, resolves, contacts, executes, or downloads
anything. Submitted values are treated as untrusted data throughout.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from .database import IntelDatabase, get_default_database
from .models import IntelRecord


def _normalize_host(raw_host: str) -> str:
    host = (raw_host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


def _registrable_domain(host: str) -> str:
    """Naive eTLD+1 (last two labels).

    Limitation: multi-level public suffixes (e.g. ``co.uk``) are not
    special-cased. Safe direction: it may miss a match, never fabricate one
    via substring comparison.
    """
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return host
    return ".".join(labels[-2:])


def _empty() -> dict:
    return {"matched": False, "findings": []}


def _hit(record: IntelRecord) -> dict:
    return {"matched": True, "findings": [record.to_dict()]}


def match_url(raw_url: str, db: IntelDatabase | None = None) -> dict:
    """Match a URL's hostname against local intelligence (evidence only)."""
    database = db or get_default_database()
    text = (raw_url or "").strip()
    if not text:
        return _empty()
    candidate = text if "://" in text else "https://" + text
    try:
        host = _normalize_host(urlsplit(candidate).hostname or "")
    except ValueError:
        return _empty()
    if not host:
        return _empty()
    record = database.lookup_hostname(host)
    if record is not None:
        return _hit(record)
    record = database.lookup_domain(_registrable_domain(host))
    if record is not None:
        return _hit(record)
    return _empty()


def match_upi(raw_uri: str, db: IntelDatabase | None = None) -> dict:
    """Match a UPI payee address against local intelligence (evidence only)."""
    database = db or get_default_database()
    text = (raw_uri or "").strip()
    if not text or not text.lower().startswith("upi://"):
        return _empty()
    try:
        query = urlsplit(text).query if "?" in text else ""
        values = {k.lower(): v for k, v in parse_qsl(query, keep_blank_values=True)}
    except ValueError:
        return _empty()
    payee = (values.get("pa") or "").strip().lower()
    if not payee or payee.count("@") != 1:
        return _empty()
    record = database.lookup_upi_handle(payee)
    return _hit(record) if record is not None else _empty()
