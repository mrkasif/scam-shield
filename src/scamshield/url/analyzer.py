"""URL normalization and orchestration (static only — never fetches the URL)."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from .detectors import Finding, run_all_detectors


def normalize_url(raw_url: str) -> str:
    """Normalize user input without visiting it.

    - strips whitespace
    - prepends https:// when the scheme is missing
    - lowercases scheme and host
    - drops the fragment (never sent to a server anyway)
    """
    cleaned = (raw_url or "").strip()
    if not cleaned:
        raise ValueError("URL must not be empty.")
    if "://" not in cleaned:
        cleaned = "https://" + cleaned
    parts = urlsplit(cleaned)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("Only http(s) URLs are supported.")
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError("URL must include a hostname.")
    # Rebuild netloc preserving userinfo/port but normalized host.
    netloc = host
    if parts.username:
        netloc = parts.username + (f":{parts.password}" if parts.password else "") + "@" + netloc
    if parts.port:
        netloc += f":{parts.port}"
    normalized = urlunsplit((scheme, netloc, parts.path or "", parts.query or "", ""))
    return normalized


def analyze_url_parts(raw_url: str) -> tuple[str, list[Finding]]:
    """Return (normalized_url, findings). Raises ValueError on bad input."""
    normalized = normalize_url(raw_url)
    findings = run_all_detectors(raw_url.strip(), normalized)
    return normalized, findings


def is_url_text(payload: str) -> str | None:
    """Return ``payload`` if it is an http(s) URL, else None.

    Canonical URL-ness check shared by the QR classifier and the unified
    Smart Scanner so the definition can never drift between modules.
    Plain text containing whitespace is never treated as a URL.
    """
    text = (payload or "").strip()
    if not text or re.search(r"\s", text):
        return None
    try:
        normalized = normalize_url(text)
    except ValueError:
        return None
    parts = urlsplit(normalized)
    if "://" not in text and parts.username:
        # Schemaless text such as "mailto:a@b.com" only looks like a URL
        # because the prepended scheme turned its prefix into userinfo.
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    try:
        ipaddress.ip_address(host.strip("[]"))
        return text
    except ValueError:
        pass
    return text if ("." in host or host == "localhost") else None
