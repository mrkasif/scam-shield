"""Public facade: URL analysis plus the unified Smart Scanner router."""

from __future__ import annotations

import logging
import re

from .scoring import clamp_score, pick_category, risk_level
from .url.analyzer import analyze_url_parts, is_url_text

logger = logging.getLogger("scamshield")

_SCHEME_LIKE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]{1,19}:")

_TEXT_NOTE = (
    "Plain text carries no link or payment score, and it is NOT marked "
    "safe. Read it critically; text can still carry scam instructions."
)


def analyze_url(raw_url: str) -> dict:
    """Statically analyze ``raw_url`` and explain the score.

    Returns keys: normalized_url, score, risk_level, category,
    suspicious, reasons, detected_indicators.
    """
    normalized, findings = analyze_url_parts(raw_url)
    total = clamp_score(sum(f.points for f in findings))
    level = risk_level(total)
    codes = [f.code for f in findings]
    reasons = [f.reason for f in findings]
    if not reasons:
        reasons = ["No phishing indicators detected in static analysis."]
    return {
        "normalized_url": normalized,
        "score": total,
        "risk_level": level,
        "category": pick_category(set(codes), total),
        "suspicious": level != "GREEN",
        "reasons": reasons,
        "detected_indicators": codes,
    }


def detect_input_type(text: str) -> str:
    """Deterministically classify raw text as url, upi, text, or unknown.

    - ``upi``: starts with the ``upi://`` scheme (validated later by the
      UPI analyzer, so a UPI URI is never mistaken for a URL).
    - ``url``: passes the shared URL-ness check.
    - ``unknown``: empty, or a non-web scheme such as ``mailto:``/``ftp:``.
    - ``text``: anything else (plain human-readable text).
    """
    stripped = (text or "").strip()
    if not stripped:
        return "unknown"
    if stripped.lower().startswith("upi://"):
        return "upi"
    if is_url_text(stripped) is not None:
        return "url"
    if _SCHEME_LIKE_RE.match(stripped):
        return "unknown"
    return "text"


def _external_url_intel(url_text: str) -> dict:
    """Optional URLhaus lookup for URL scans (one call, fail-safe).

    Any provider problem degrades to ``available: false`` — scanning
    always succeeds. UPI/text/QR-non-URL inputs never reach this function.
    """
    from .intel.providers.urlhaus import check_url as check_urlhaus

    try:
        return check_urlhaus(url_text)
    except Exception as exc:  # noqa: BLE001 - provider must not break scans
        logger.warning("External intel failed safely: %s", type(exc).__name__)
        return {
            "provider": "urlhaus",
            "configured": True,
            "available": False,
            "matched": False,
            "findings": [],
            "error": "provider_error",
        }


def smart_scan_text(text: str) -> dict:
    """Route text to the correct existing analyzer (thin facade, no rules).

    Returns the ``{"input_type": ..., "success": True, "result": ...}``
    envelope. URL results additionally carry evidence-only
    ``threat_intelligence`` (``{"local": ..., "external": ...}``);
    analyzer verdicts are never modified. Raises ``ValueError`` for empty
    or unsupported input.
    """
    from .intel.matcher import match_upi, match_url
    from .upi.analyzer import analyze_upi  # local import: no new dependency weight

    stripped = (text or "").strip()
    if not stripped:
        raise ValueError("Input must not be empty.")
    kind = detect_input_type(stripped)
    if kind == "url":
        result = analyze_url(stripped)
        result["threat_intelligence"] = {
            "local": match_url(stripped),
            "external": _external_url_intel(stripped),
        }
        return {"input_type": "url", "success": True, "result": result}
    if kind == "upi":
        result = analyze_upi(stripped)
        result["threat_intelligence"] = {"local": match_upi(stripped)}
        return {"input_type": "upi", "success": True, "result": result}
    if kind == "text":
        return {
            "input_type": "text",
            "success": True,
            "result": {"type": "text", "content": stripped, "note": _TEXT_NOTE},
        }
    raise ValueError(
        "Unsupported input: submit an http(s) URL, a upi:// URI, a QR image, or plain text."
    )


def smart_scan_qr(image_bytes: bytes) -> dict:
    """Route a QR image through the existing QR analyzer (thin facade).

    Returns the ``{"input_type": "qr", "success": True, "result": ...}``
    envelope; the inner result keeps the QR analyzer's own shape
    (``type`` url/upi/text/unknown/empty). URL payloads additionally
    carry evidence-only local + external ``threat_intelligence``; UPI
    payloads carry local only (UPI is never sent externally). Raises
    ``ValueError`` for invalid images or when no QR code is found.
    """
    from .intel.matcher import match_upi, match_url
    from .qr.analyzer import analyze_qr_image  # local import: avoids a cycle

    result = analyze_qr_image(image_bytes)
    payload = result.get("payload") or ""
    if result.get("type") == "url":
        result["threat_intelligence"] = {
            "local": match_url(payload),
            "external": _external_url_intel(payload),
        }
    elif result.get("type") == "upi":
        result["threat_intelligence"] = {"local": match_upi(payload)}
    return {"input_type": "qr", "success": True, "result": result}
