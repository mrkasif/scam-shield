"""Deterministic static UPI payment-URI analyzer.

Inspects UPI URIs such as
``upi://pay?pa=merchant@bank&pn=Name&am=999&cu=INR&tn=Note`` and flags
suspicious payment characteristics with an explainable score.

It NEVER initiates a payment, contacts a bank or handle, performs any
network request, verifies that an account exists, or claims a UPI ID is
legitimate merely because its syntax is valid. Static analysis only.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from ..scoring import clamp_score, risk_level

COMPONENT_KEYS = ("pa", "pn", "am", "cu", "tn", "mc", "tr", "tid")

# Query parameters defined by UPI deep-linking practice; anything else is
# reported (but only mildly penalized — apps add custom fields legitimately).
_KNOWN_PARAMS = frozenset(
    {
        "pa", "pn", "am", "cu", "tn", "mc", "tr", "tid",
        "mode", "purpose", "orgid", "sign", "url", "refurl",
        "refid", "msid", "mtid", "mam",
    }
)

_PA_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}@[A-Za-z]{2,32}$")
_ENCODED_RE = re.compile(r"%([0-9a-fA-F]{2})")
_SAFE_DECODED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 _.-"
    ",':&"
)

_KYC_TERMS = ("kyc", "verify", "verification", "verified", "ekyc")
_IMPERSONATION_TERMS = (
    "rbi", "reserve bank", "police", "cbi", "income tax",
    "customer care", "support officer", "kyc officer", "army",
)
_URGENCY_TERMS = (
    "urgent", "immediately", "instantly", "hurry", "last chance",
    "expire", "expiring", "blocked", "block", "suspend", "suspended",
    "freeze", "frozen", "within", "today only", "act now",
)
_REWARD_TERMS = (
    "prize", "winner", "lottery", "reward", "cashback", "cash back",
    "refund", "offer", "bonus", "gift", "congratulations", "won ",
)

_HIGH_AMOUNT = 100000.0  # Rs. 1 lakh — unusual for a QR-sticker payment


def _parse_uri(raw_uri: str) -> tuple[str, list[tuple[str, str]]]:
    """Split a UPI URI into (action, query pairs). Raises ValueError."""
    text = (raw_uri or "").strip()
    if not text:
        raise ValueError("UPI URI must not be empty.")
    if re.search(r"\s", text):
        raise ValueError("Not a valid UPI URI: whitespace is not allowed.")
    parts = urlsplit(text)
    if parts.scheme.lower() != "upi":
        raise ValueError("Not a UPI URI: scheme must be 'upi://'.")
    action = (parts.hostname or "").lower()
    query = parts.query
    if not action and not query:
        raise ValueError("Not a valid UPI URI: nothing to analyze.")
    try:
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError as exc:
        raise ValueError("Not a valid UPI URI: malformed query string.") from exc
    return action, pairs


def _find_terms(haystack: str, terms: tuple[str, ...]) -> list[str]:
    lowered = haystack.lower()
    return sorted({term for term in terms if term in lowered})


def _suspicious_encodings(raw_query: str, keys: set[str]) -> list[str]:
    """Find %XX in pa/pn/tn raw values decoding to non-plaintext chars.

    Ordinary ``%20`` spaces (as in ``Merchant%20Name``) are ignored; only
    encodings that hide characters like ``@ / :`` count as obfuscation.
    """
    hits: list[str] = []
    for chunk in raw_query.split("&"):
        if "=" not in chunk:
            continue
        key, _, value = chunk.partition("=")
        if key.lower() not in keys:
            continue
        for match in _ENCODED_RE.finditer(value):
            char = chr(int(match.group(1), 16))
            if char not in _SAFE_DECODED:
                hits.append(f"{match.group(0).upper()} in '{key}'")
    seen: list[str] = []
    for hit in hits:
        if hit not in seen:
            seen.append(hit)
    return seen[:3]


def raw_query(text: str) -> str:
    """Return the raw query substring of a URI (helper for encoding checks)."""
    return urlsplit(text).query if "?" in text else ""


def _pick_category(codes: set[str], score: int) -> str:
    if "missing_pa" in codes or "malformed_pa" in codes:
        return "invalid_payee"
    if "impersonation" in codes or "kyc_language" in codes:
        return "impersonation_scam"
    if "reward_language" in codes:
        return "reward_lure"
    if "urgency_language" in codes:
        return "pressure_tactic"
    if score >= 30:
        return "suspicious_payment"
    return "normal"


def analyze_upi(raw_uri: str) -> dict:
    """Statically analyze a UPI payment URI into an explainable verdict."""
    action, pairs = _parse_uri(raw_uri)
    text = raw_uri.strip()

    # First value wins for repeated keys (matches UPI app behavior).
    values: dict[str, str] = {}
    for key, value in pairs:
        key = key.lower()
        if key not in values:
            values[key] = value

    components = {name: values.get(name) for name in COMPONENT_KEYS}

    points = 0
    reasons: list[str] = []
    codes: list[str] = []

    def add(code: str, score: int, reason: str) -> None:
        nonlocal points
        codes.append(code)
        points += score
        reasons.append(reason)

    # --- URI shape ---
    if action != "pay":
        shown = action if action else "(missing)"
        add(
            "unexpected_action",
            15,
            f"UPI action is '{shown}' instead of the standard "
            "'pay'; unexpected actions deserve extra scrutiny.",
        )

    # --- payee address ---
    pa = (values.get("pa") or "").strip()
    if not pa:
        add(
            "missing_pa",
            30,
            "No payee address (pa): it is impossible to tell who receives "
            "the money. Never pay a request without a visible payee.",
        )
    elif not _PA_RE.match(pa):
        add(
            "malformed_pa",
            30,
            f"Payee UPI ID '{pa}' is malformed. Valid IDs look like "
            "'name@bankhandle' (letters/digits/._- before @, bank handle after). "
            "Never pay when the recipient cannot be verified.",
        )
    else:
        handle = pa.rsplit("@", 1)[1]
        if "." in handle:
            add(
                "pa_host_like",
                15,
                f"Payee handle '{handle}' looks like an email/domain rather "
                "than a bank handle — a known impersonation trick.",
            )
        if re.search(r"[@]{2,}|//|\?|https?|%[0-9a-fA-F]{2}", pa):
            add(
                "pa_suspicious_chars",
                20,
                "Payee address contains suspicious characters or URL-like "
                "content; genuine UPI IDs are simple 'name@handle' values.",
            )

    # --- amount / currency ---
    am = (values.get("am") or "").strip()
    if am:
        try:
            amount = float(am)
            if amount <= 0:
                raise ValueError
            if amount >= _HIGH_AMOUNT:
                add(
                    "high_amount",
                    10,
                    f"Amount Rs. {am} is unusually high for a routine QR "
                    "payment — double-check the figure before paying.",
                )
        except ValueError:
            add(
                "bad_amount",
                15,
                f"Amount '{am}' is not a valid positive number; odd amount "
                "formatting is used to confuse payers.",
            )
    cu = (values.get("cu") or "").strip()
    if cu and cu.upper() != "INR":
        add(
            "foreign_currency",
            20,
            f"Currency '{cu}' is not INR; domestic UPI payments should be "
            "in rupees.",
        )

    # --- language in payee name / note ---
    language = f"{values.get('pn') or ''} {values.get('tn') or ''}"
    kyc = _find_terms(language, _KYC_TERMS)
    if kyc:
        add(
            "kyc_language",
            30,
            "Payment text uses KYC/verification language "
            f"({', '.join(kyc)}); banks never collect KYC over UPI payments.",
        )
    impersonating = _find_terms(language, _IMPERSONATION_TERMS)
    if impersonating:
        add(
            "impersonation",
            30,
            "Payment text invokes authority figures "
            f"({', '.join(impersonating)}) — a classic impersonation scam.",
        )
    urgency = _find_terms(language, _URGENCY_TERMS)
    if urgency:
        add(
            "urgency_language",
            15,
            "Payment text pressures quick action "
            f"({', '.join(urgency)}); scammers manufacture urgency.",
        )
    reward = _find_terms(language, _REWARD_TERMS)
    if reward:
        add(
            "reward_language",
            30,
            "Payment text promises prizes/refunds/rewards "
            f"({', '.join(reward)}); payouts never require you to pay first.",
        )

    # --- obfuscation / parameter hygiene ---
    hidden = _suspicious_encodings(raw_query(text), {"pa", "pn", "tn"})
    if hidden:
        add(
            "obfuscated_content",
            10,
            f"Payment field hides characters via encoding ({hidden[0]}); "
            "obfuscation is used to disguise the real payee or message.",
        )
    if len(pairs) > 10:
        add(
            "excessive_params",
            10,
            f"URI carries {len(pairs)} parameters (normally a handful); "
            "bloated requests can hide malicious fields.",
        )
    unknown = sorted({k for k, _ in pairs if k.lower() not in _KNOWN_PARAMS})
    if unknown:
        extra = min(5 * len(unknown), 10)
        points += extra
        codes.append("unknown_params")
        reasons.append(
            "URI contains unrecognized parameters "
            f"({', '.join(unknown[:5])}); unknown fields merit caution."
        )

    score = clamp_score(points)
    level = risk_level(score)
    if not reasons:
        reasons = ["No suspicious payment characteristics detected in static analysis."]

    return {
        "type": "upi",
        "raw_uri": text,
        "components": components,
        "score": score,
        "risk_level": level,
        "category": _pick_category(set(codes), score),
        "suspicious": level != "GREEN",
        "reasons": reasons,
        "detected_indicators": codes,
    }
