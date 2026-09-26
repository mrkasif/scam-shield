"""Individual deterministic detectors for static URL analysis.

Each detector is a pure function that inspects the parsed URL and
returns a ``Finding`` with a controlled point value, a short machine
``code`` and a human-readable ``reason``. No network calls are made.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit


@dataclass(frozen=True)
class Finding:
    code: str
    points: int
    reason: str


SUSPICIOUS_KEYWORDS = (
    "login",
    "log-in",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "payment",
    "pay",
    "bank",
    "confirm",
    "password",
    "credential",
    "wallet",
    "invoice",
    "refund",
    "suspend",
    "urgent",
    "bonus",
    "prize",
    "free",
    "winner",
    "kyc",
    "upi",
)

DANGEROUS_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".cmd", ".msi", ".apk", ".jar",
    ".js", ".jse", ".vbs", ".vbe", ".ps1", ".zip", ".rar",
    ".7z", ".iso", ".img", ".dll", ".com", ".pif",
)

BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "google": "google.com",
    "gmail": "google.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "outlook": "microsoft.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "whatsapp": "whatsapp.com",
    "phonepe": "phonepe.com",
    "paytm": "paytm.com",
    "gpay": "google.com",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "sbi": "onlinesbi.com",
    "axis": "axisbank.com",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz",
    "click", "country", "work", "party", "gdn",
    "loan", "win", "review", "stream", "download",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st",
    "tiny.cc", "bitly.com",
}

SUSPICIOUS_QUERY_KEYS = {
    "redirect", "redirect_uri", "redirecturl", "next", "continue",
    "return", "returnurl", "goto", "rurl", "url", "u", "dest",
    "destination", "token", "session", "sessionid", "password",
    "card", "account", "login",
}

_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")


def _host_parts(host: str) -> list[str]:
    return [p for p in host.split(".") if p]


def detect_ip_host(host: str) -> Finding | None:
    """IP address used instead of a domain name."""
    cleaned = host.strip("[]").lower()
    try:
        ipaddress.ip_address(cleaned)
        return Finding(
            code="ip_host",
            points=25,
            reason="URL uses an IP address instead of a domain name, "
            "a common phishing/malware hosting trick.",
        )
    except ValueError:
        return None


def detect_at_symbol(raw_url: str) -> Finding | None:
    if "@" in raw_url:
        return Finding(
            code="at_symbol",
            points=25,
            reason="URL contains '@', which browsers interpret as "
            "userinfo — attackers use it to hide the real destination.",
        )
    return None


def detect_punycode(host: str) -> Finding | None:
    if "xn--" in host.lower():
        return Finding(
            code="punycode",
            points=25,
            reason="Hostname uses punycode (xn--), often used for "
            "look-alike / homograph impersonation domains.",
        )
    return None


def detect_no_tls(scheme: str) -> Finding | None:
    if scheme == "http":
        return Finding(
            code="no_tls",
            points=10,
            reason="URL uses plain HTTP instead of HTTPS; credentials or "
            "payments on such pages can be intercepted.",
        )
    return None


def detect_unusual_port(parts) -> Finding | None:
    try:
        port = parts.port
    except ValueError:
        return Finding(
            code="unusual_port",
            points=15,
            reason="URL specifies an invalid/unusual port.",
        )
    if port is None:
        return None
    if port in (80, 443):
        return None
    return Finding(
        code="unusual_port",
        points=15,
        reason=f"URL uses unusual port {port}; phishing kits and malware "
        "often hide on non-standard ports.",
    )


def detect_long_url(raw_url: str) -> Finding | None:
    n = len(raw_url)
    if n > 200:
        return Finding("long_url", 15,
                        f"URL is very long ({n} chars); long URLs are used "
                        "to bury the real domain and payload.")
    if n > 125:
        return Finding("long_url", 10,
                        f"URL is long ({n} chars), which can hide the true destination.")
    if n > 75:
        return Finding("long_url", 5,
                        f"URL is longer than typical ({n} chars).")
    return None


def detect_excessive_subdomains(host: str) -> Finding | None:
    dots = host.count(".")
    if dots >= 4:
        return Finding("excessive_subdomains", 15,
                        f"Hostname has {dots + 1} labels (many subdomains), "
                        "often used to fake a trusted domain.")
    if dots == 3:
        return Finding("excessive_subdomains", 10,
                        "Hostname has 4 labels; check the actual registrable "
                        "domain (last two labels).")
    return None


def detect_suspicious_chars(host: str, raw_url: str) -> Finding | None:
    hyphens = host.count("-")
    if hyphens >= 4:
        return Finding("suspicious_chars", 10,
                        f"Hostname contains {hyphens} hyphens; excessive hyphens "
                        "are typical of look-alike domains.")
    if hyphens >= 2:
        return Finding("suspicious_chars", 5,
                        "Hostname contains multiple hyphens, common in impersonation domains.")
    if "_" in host:
        return Finding("suspicious_chars", 5,
                        "Hostname contains underscores, which are unusual in legitimate domains.")
    if raw_url.count("//") > 1 or "\\\\" in raw_url:
        return Finding("suspicious_chars", 5,
                        "URL contains suspicious extra slashes/backslashes.")
    return None


def detect_encoded_chars(raw_url: str) -> Finding | None:
    matches = _ENCODED_RE.findall(raw_url)
    if len(matches) >= 3:
        return Finding("encoded_chars", 15,
                        f"URL contains {len(matches)} percent-encoded sequences; "
                        "encoding is used to obfuscate malicious payloads.")
    if matches:
        return Finding("encoded_chars", 10,
                        "URL contains percent-encoded characters that can hide "
                        "the true path or query.")
    return None


def detect_keywords(raw_url: str) -> Finding | None:
    from urllib.parse import unquote

    lowered = raw_url.lower()
    try:
        decoded = unquote(lowered)
    except ValueError:
        decoded = lowered
    # Scan both raw and percent-decoded text so %70aypal-style
    # obfuscation cannot evade keyword matching.
    hits = sorted({kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered or kw in decoded})
    if not hits:
        return None
    # Keyword evidence saturates at two distinct lure terms: further terms
    # add no weight on their own, so an otherwise clean URL carrying only
    # checkout-style words cannot reach YELLOW without corroborating
    # structural signals (odd host, HTTP, obfuscation, …).
    points = min(8 * len(hits), 16)
    shown = ", ".join(hits[:5])
    return Finding(
        code="suspicious_keywords",
        points=points,
        reason=f"URL contains lure keywords ({shown}) often used in "
        "phishing lures (fake login/verify/payment pages).",
    )


def detect_dangerous_extension(path: str) -> Finding | None:
    lowered = path.lower().split("?")[0].rstrip("/")
    for ext in DANGEROUS_EXTENSIONS:
        if lowered.endswith(ext):
            return Finding(
                code="dangerous_extension",
                points=20,
                reason=f"URL points directly to a '{ext}' file, which can be "
                "malware or an unwanted executable.",
            )
    return None


def _levenshtein_at_most_one(a: str, b: str) -> bool:
    """True when edit distance between a and b is 0 or 1 (no new deps)."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    # Substitution case (same length): at most one differing char.
    if la == lb:
        return sum(1 for x, y in zip(a, b) if x != y) <= 1
    # Insertion/deletion case: the longer string minus one char equals the other.
    longer, shorter = (a, b) if la > lb else (b, a)
    for i in range(len(longer)):
        if longer[:i] + longer[i + 1:] == shorter:
            return True
    return False


def detect_brand_impersonation(host: str) -> Finding | None:
    lowered_host = host.lower()
    for brand, official in BRAND_DOMAINS.items():
        if lowered_host == official or lowered_host.endswith("." + official):
            continue
        for label in lowered_host.split("."):
            for token in re.split(r"[-_]+", label):
                if not token:
                    continue
                if token == brand:
                    return Finding(
                        code="brand_impersonation",
                        points=20,
                        reason=f"Hostname uses '{token}' but is not the official "
                        f"domain ({official}); likely brand impersonation.",
                    )
                # Near-miss look-alikes (paypa1, gogle): a single typo away
                # from the brand. Deliberately NOT plain substring matching,
                # so legitimate longer words containing a brand name
                # (icicidirect, myapplerepairshop) are left alone. The
                # same-first-letter rule additionally excludes coincidental
                # collisions such as mail/email vs gmail, while genuine
                # typosquats overwhelmingly preserve the first letter.
                if (
                    len(token) >= 4
                    and len(brand) >= 4
                    and token[0] == brand[0]
                    and _levenshtein_at_most_one(token, brand)
                ):
                    return Finding(
                        code="brand_impersonation",
                        points=20,
                        reason=f"Hostname uses '{token}', a close look-alike of "
                        f"'{brand}' (official domain: {official}); likely "
                        "brand impersonation.",
                    )
    return None


def detect_suspicious_query(query: str) -> Finding | None:
    if not query:
        return None
    points = 0
    reasons: list[str] = []
    try:
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError:
        pairs = []
    keys = {k.lower() for k, _ in pairs}
    risky = sorted(keys & SUSPICIOUS_QUERY_KEYS)
    if risky:
        points += 10
        reasons.append("query uses risky keys (" + ", ".join(risky[:5]) + ") such as redirects/token capture")
    if len(query) > 100:
        points += 5
        reasons.append(f"query string is long ({len(query)} chars)")
    if not reasons:
        return None
    return Finding(
        code="suspicious_query",
        points=min(points, 15),
        reason="Suspicious query parameters: " + "; ".join(reasons) + ".",
    )


def detect_hostname_anomalies(host: str) -> Finding | None:
    labels = _host_parts(host.lower())
    if not labels:
        return None
    points = 0
    notes: list[str] = []
    longest = max(len(label) for label in labels)
    if longest > 30:
        points += 10
        notes.append(f"a domain label is abnormally long ({longest} chars)")
    digits = sum(c.isdigit() for c in host)
    if digits >= 5:
        points += 10
        notes.append("hostname contains many digits (often auto-generated phishing domains)")
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        points += 10
        notes.append(f"top-level domain '.{tld}' is frequently abused by scammers")
    if len(host) > 50:
        points += 5
        notes.append(f"hostname is unusually long ({len(host)} chars)")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        points += 5
        notes.append("a domain label starts/ends with a hyphen")
    if not notes:
        return None
    return Finding(
        code="hostname_anomaly",
        points=min(points, 20),
        reason="Hostname anomaly: " + "; ".join(notes) + ".",
    )


def detect_shortener(host: str) -> Finding | None:
    if host.lower() in URL_SHORTENERS:
        return Finding(
            code="url_shortener",
            points=10,
            reason="URL uses a link shortener, which hides the final destination.",
        )
    return None


def run_all_detectors(raw_url: str, normalized_url: str) -> list[Finding]:
    """Run every detector against the URL. Pure/static — no network."""
    parts = urlsplit(normalized_url)
    host = (parts.hostname or "").lower()
    findings: list[Finding] = []
    checks = [
        detect_ip_host(host),
        detect_at_symbol(raw_url),
        detect_punycode(host),
        detect_no_tls(parts.scheme),
        detect_unusual_port(parts),
        detect_long_url(raw_url),
        detect_excessive_subdomains(host),
        detect_suspicious_chars(host, raw_url),
        detect_encoded_chars(raw_url),
        detect_keywords(raw_url),
        detect_dangerous_extension(parts.path),
        detect_brand_impersonation(host),
        detect_suspicious_query(parts.query),
        detect_hostname_anomalies(host),
        detect_shortener(host),
    ]
    for finding in checks:
        if finding is not None:
            findings.append(finding)
    return findings
