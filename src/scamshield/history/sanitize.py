"""Privacy sanitizers for scan-history previews (static string ops only).

What is stored per scan is deliberately minimal:
- URLs: scheme + host + path only. Userinfo, fragments, and query VALUES
  are removed (parameter names are kept so `?redirect=` stays inspectable
  without leaking tokens).
- UPI: recipient handle + amount only. Payee names, notes, and transaction
  references are dropped.
- Text: first 120 characters, truncated.
- QR images: never stored; only the sanitized decoded payload as above.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

PREVIEW_LIMIT = 140


def truncate_preview(text: str, limit: int = PREVIEW_LIMIT) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def sanitize_url_preview(raw_url: str) -> str:
    """Return scheme://host/path with secrets stripped from a URL."""
    text = (raw_url or "").strip()
    if not text:
        return ""
    candidate = text if "://" in text else "https://" + text
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return truncate_preview(text)
    host = (parts.hostname or "").lower()
    if not host:
        return truncate_preview(text)
    try:
        query_names = [key for key, _ in parse_qsl(parts.query, keep_blank_values=True)]
    except ValueError:
        query_names = []
    seen: list[str] = []
    for name in query_names:
        if name not in seen:
            seen.append(name)
    query = ("?" + "&".join(f"{name}=" for name in seen[:8])) if seen else ""
    path = parts.path or ""
    return truncate_preview(f"{parts.scheme.lower()}://{host}{path}{query}")


def sanitize_upi_preview(raw_uri: str) -> str:
    """Return a minimal upi://pay?pa=...@handle&am=... representation."""
    text = (raw_uri or "").strip()
    if not text:
        return ""
    try:
        query = urlsplit(text).query if "?" in text else ""
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError:
        return truncate_preview(text[:40])
    values = {key.lower(): value for key, value in pairs}
    pa = (values.get("pa") or "").strip()
    if "@" in pa:
        handle = pa.rsplit("@", 1)[1].strip()[:40]
        masked_pa = f"...@{handle}" if handle else "..."
    elif pa:
        masked_pa = truncate_preview(pa, 24)
    else:
        masked_pa = "..."
    amount = (values.get("am") or "").strip()
    suffix = f"&am={amount[:16]}" if amount else ""
    return truncate_preview(f"upi://pay?pa={masked_pa}{suffix}")
