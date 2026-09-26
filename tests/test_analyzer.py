"""Tests for the ScamShield static URL analyzer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from scamshield.analyzer import analyze_url
from scamshield.scoring import clamp_score, risk_level


def test_valid_url_is_green():
    result = analyze_url("https://example.com")
    assert result["risk_level"] == "GREEN"
    assert result["score"] <= 29
    assert result["suspicious"] is False
    assert result["normalized_url"] == "https://example.com"


def test_suspicious_url_is_yellow_or_red():
    result = analyze_url("http://paypal-secure-login-verify-update.example.com/login?redirect=evil.com")
    assert result["risk_level"] in ("YELLOW", "RED")
    assert result["suspicious"] is True
    assert "suspicious_keywords" in result["detected_indicators"]
    assert len(result["reasons"]) >= 1


def test_ip_based_url_flagged():
    result = analyze_url("http://192.168.1.10/login")
    assert "ip_host" in result["detected_indicators"]
    assert result["score"] >= 25
    assert result["suspicious"] is True


def test_at_symbol_url_flagged():
    result = analyze_url("https://example.com@evil.com/login")
    assert "at_symbol" in result["detected_indicators"]
    assert result["suspicious"] is True


def test_encoded_url_flagged():
    result = analyze_url("https://example.com/%70%61%79%70%61%6c/login")
    assert "encoded_chars" in result["detected_indicators"]
    assert result["suspicious"] is True


def test_score_boundaries_clamped():
    assert clamp_score(-5) == 0
    assert clamp_score(250) == 100
    assert clamp_score(42) == 42
    # Worst-case phishing URL must never exceed 100.
    result = analyze_url(
        "http://192.168.1.1:8080/paypal-secure-login-verify-payment-update@evil.com"
        "/malware.exe?redirect=evil&token=abc%20%41%42%43"
    )
    assert 0 <= result["score"] <= 100


def test_risk_zone_calculation():
    assert risk_level(0) == "GREEN"
    assert risk_level(29) == "GREEN"
    assert risk_level(30) == "YELLOW"
    assert risk_level(69) == "YELLOW"
    assert risk_level(70) == "RED"
    assert risk_level(100) == "RED"


def test_brand_substring_in_longer_word_not_flagged():
    for url in ("https://icicidirect.com", "https://myapplerepairshop.com"):
        result = analyze_url(url)
        assert "brand_impersonation" not in result["detected_indicators"], url


def test_brand_lookalike_still_flagged():
    for url in ("https://paypa1.com", "https://paypal-secure.tk/login"):
        result = analyze_url(url)
        assert "brand_impersonation" in result["detected_indicators"], url


def test_checkout_url_stays_green():
    result = analyze_url("https://shop.example.com/checkout/payment?account=guest&login=false")
    assert result["risk_level"] == "GREEN"
    assert result["category"] != "phishing_lure"


def test_response_shape_explains_score():
    result = analyze_url("https://example.com")
    for key in (
        "normalized_url",
        "score",
        "risk_level",
        "category",
        "suspicious",
        "reasons",
        "detected_indicators",
    ):
        assert key in result
    assert isinstance(result["reasons"], list) and result["reasons"]
