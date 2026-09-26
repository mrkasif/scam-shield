"""Transparent rule-based scoring for ScamShield."""

from __future__ import annotations

GREEN_MAX = 29
YELLOW_MAX = 69


def clamp_score(score: int) -> int:
    return max(0, min(100, int(score)))


def risk_level(score: int) -> str:
    """Map a 0-100 score to a GREEN/YELLOW/RED zone."""
    score = clamp_score(score)
    if score <= GREEN_MAX:
        return "GREEN"
    if score <= YELLOW_MAX:
        return "YELLOW"
    return "RED"


def pick_category(codes: set[str], score: int) -> str:
    """Pick a single best-fit threat category from detector codes."""
    if "punycode" in codes or "brand_impersonation" in codes:
        return "brand_impersonation"
    if "ip_host" in codes:
        return "ip_host"
    if "dangerous_extension" in codes:
        return "malware_delivery"
    if "at_symbol" in codes:
        return "credential_phishing"
    if "suspicious_keywords" in codes and score >= 30:
        return "phishing_lure"
    if "url_shortener" in codes or "suspicious_query" in codes:
        return "suspicious_redirect"
    if score >= 70:
        return "phishing"
    if score >= 30:
        return "suspicious"
    return "benign"
