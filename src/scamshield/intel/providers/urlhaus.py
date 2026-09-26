"""URLhaus Community API provider (optional, evidence-only).

Uses the documented automated-lookup endpoint
(``POST https://urlhaus-api.abuse.ch/v1/url/`` with an ``Auth-Key`` header)
— never the website, never the submitted destination.

Authentication comes ONLY from the ``SCAMSHIELD_URLHAUS_AUTH_KEY``
environment variable. When it is missing the provider reports
``configured: false`` and ScamShield works exactly as before.

Privacy — what is sent to URLhaus per lookup:
- scheme + host (lowercased) + path + non-sensitive query parameters,
- NO fragment, NO userinfo, and known-sensitive query values
  (token/session/auth/password/api-key style) replaced with "...".
  This may reduce exact-match hits; privacy wins by design.

What is NEVER sent: arbitrary text, UPI data, QR images, passwords,
history records, or the API key anywhere except the request header.

Fail-safe: one lookup per scan, 5 s timeout, no retries, every failure
maps to a clean ``available: false`` envelope — scanning always succeeds.
"""

from __future__ import annotations

import logging
import os
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

logger = logging.getLogger("scamshield.intel.urlhaus")

NAME = "urlhaus"
API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
ENV_VAR = "SCAMSHIELD_URLHAUS_AUTH_KEY"
TIMEOUT_SECONDS = 5.0

# Query parameters whose VALUES are never transmitted (names are kept so
# the lookup URL stays structurally close to the submitted one).
_SENSITIVE_PARAMS = frozenset(
    {
        "token", "session", "sessionid", "sid", "auth", "password", "passwd",
        "apikey", "api_key", "api-key", "access_token", "secret", "otp",
    }
)


def sanitize_for_lookup(raw_url: str) -> str:
    """Build the privacy-trimmed URL actually sent to URLhaus."""
    text = (raw_url or "").strip()
    if not text:
        raise ValueError("URL must not be empty.")
    candidate = text if "://" in text else "https://" + text
    try:
        parts = urlsplit(candidate)
    except ValueError as exc:
        raise ValueError("Not a valid URL.") from exc
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http(s) URLs can be looked up.")
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError("URL must include a hostname.")
    try:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError as exc:
        raise ValueError("Not a valid URL.") from exc
    cleaned = [
        (key, "..." if key.lower() in _SENSITIVE_PARAMS else value)
        for key, value in pairs
    ]
    netloc = host
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("URL specifies an invalid port.") from exc
    if port is not None:
        netloc += f":{port}"
    # userinfo dropped, fragment dropped (urlunsplit with "").
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "", urlencode(cleaned), ""))


def disabled_result() -> dict:
    return {
        "provider": NAME,
        "configured": False,
        "available": False,
        "matched": False,
        "findings": [],
        "error": None,
    }


def _failure(error: str) -> dict:
    return {
        "provider": NAME,
        "configured": True,
        "available": False,
        "matched": False,
        "findings": [],
        "error": error,
    }


def _query_api(lookup_url: str, auth_key: str, timeout: float) -> dict:
    """POST one lookup to URLhaus. Raises provider-mapped exceptions."""
    try:
        response = httpx.post(
            API_URL,
            data={"url": lookup_url},
            headers={"Auth-Key": auth_key},
            timeout=timeout,
        )
    except httpx.TimeoutException as exc:
        raise _ProviderError("timeout") from exc
    except httpx.RequestError as exc:
        raise _ProviderError("network_error") from exc
    if response.status_code == 429:
        raise _ProviderError("rate_limited")
    if response.status_code in (401, 403):
        raise _ProviderError("auth_failed")
    if response.status_code >= 500:
        raise _ProviderError("provider_error")
    if response.status_code != 200:
        raise _ProviderError("provider_error")
    try:
        payload = response.json()
    except ValueError as exc:
        raise _ProviderError("malformed_response") from exc
    if not isinstance(payload, dict):
        raise _ProviderError("malformed_response")
    return payload


class _ProviderError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_THREAT_TO_CATEGORY = {"malware_download": "malware"}


def _normalize_match(payload: dict, lookup_url: str) -> dict:
    threat = payload.get("threat") or "malware"
    return {
        "provider": NAME,
        "configured": True,
        "available": True,
        "matched": True,
        "findings": [
            {
                "indicator_type": "url",
                "indicator": lookup_url,
                "category": _THREAT_TO_CATEGORY.get(threat, str(threat)),
                "severity": "high",
                "confidence": None,
                "source": "URLhaus",
                "description": (
                    "URLhaus reported this URL as associated with "
                    "malware distribution."
                ),
            }
        ],
        "error": None,
    }


def check_url(url: str, timeout: float = TIMEOUT_SECONDS) -> dict:
    """Look up one URL via URLhaus. Never raises; never fetches the URL."""
    auth_key = os.environ.get(ENV_VAR, "").strip()
    if not auth_key:
        return disabled_result()
    try:
        lookup_url = sanitize_for_lookup(url)
    except ValueError:
        return {
            "provider": NAME,
            "configured": True,
            "available": False,
            "matched": False,
            "findings": [],
            "error": "invalid_input",
        }
    try:
        payload = _query_api(lookup_url, auth_key, timeout)
    except _ProviderError as exc:
        logger.warning("URLhaus lookup failed: %s", exc.code)
        return _failure(exc.code)
    status = str(payload.get("query_status") or "").lower()
    if status == "ok":
        return _normalize_match(payload, lookup_url)
    if status in ("no_results", "invalid_url"):
        return {
            "provider": NAME,
            "configured": True,
            "available": True,
            "matched": False,
            "findings": [],
            "error": None,
        }
    if "auth" in status:
        logger.warning("URLhaus lookup failed: auth_failed")
        return _failure("auth_failed")
    logger.warning("URLhaus lookup failed: provider_error")
    return _failure("provider_error")


class UrlhausProvider:
    """Object-oriented facade over :func:`check_url` (matches base.Protocol)."""

    name = NAME

    def __init__(self, timeout: float = TIMEOUT_SECONDS) -> None:
        self.timeout = timeout

    def check_url(self, url: str) -> dict:
        return check_url(url, timeout=self.timeout)
