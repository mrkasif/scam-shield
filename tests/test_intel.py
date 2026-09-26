"""Tests for the local threat-intelligence layer (Step 8, offline only)."""

import io
import sys
from pathlib import Path

import pytest
import qrcode
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from api.index import app  # noqa: E402
from scamshield.analyzer import analyze_url, smart_scan_text  # noqa: E402
from scamshield.intel import match_upi, match_url  # noqa: E402
from scamshield.upi import analyze_upi  # noqa: E402

client = TestClient(app)


@pytest.fixture(autouse=True)
def _no_urlhaus_key(monkeypatch):
    # Hermetic: a real key in the environment must never trigger network here.
    monkeypatch.delenv("SCAMSHIELD_URLHAUS_AUTH_KEY", raising=False)


def make_qr_png(data: str) -> bytes:
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# --- domain matching ---


def test_exact_domain_match():
    result = match_url("https://malicious.example/login")
    assert result["matched"] is True
    finding = result["findings"][0]
    assert finding["indicator"] == "malicious.example"
    assert finding["indicator_type"] == "domain"
    assert finding["source"] == "ScamShield Demo Intelligence"
    assert 0.0 <= finding["confidence"] <= 1.0


def test_subdomain_match():
    result = match_url("https://sub.malicious.example/path")
    assert result["matched"] is True
    assert result["findings"][0]["indicator"] == "malicious.example"


def test_unrelated_domain_no_match():
    assert match_url("https://example.com") == {"matched": False, "findings": []}


def test_substring_lookalike_no_match():
    assert match_url("https://notmalicious.example/")["matched"] is False
    assert match_url("https://malicious.example.evil.com/")["matched"] is False


def test_hostname_normalization():
    assert match_url("https://PHISHING.EXAMPLE./x")["matched"] is True
    assert match_url("https://secure.phishing.example/x")["findings"][0][
        "indicator_type"] == "hostname"


def test_hostname_record_does_not_match_parent():
    # secure.phishing.example is a hostname record: the bare parent domain
    # must not match it (only the phishing.example domain record does).
    result = match_url("https://phishing.example/")
    assert result["matched"] is True
    assert result["findings"][0]["indicator"] == "phishing.example"


# --- UPI matching ---


def test_upi_exact_handle_match():
    result = match_upi("upi://pay?pa=scammer@demoupi&am=100")
    assert result["matched"] is True
    assert result["findings"][0]["indicator_type"] == "upi_handle"


def test_upi_case_normalization():
    assert match_upi("upi://pay?pa=Scammer@DemoUPI")["matched"] is True


def test_upi_unrelated_handle_no_match():
    assert match_upi("upi://pay?pa=shop@paytm") == {"matched": False, "findings": []}


def test_upi_malformed_no_match_no_crash():
    assert match_upi("upi://pay?pa=not-an-id")["matched"] is False
    assert match_upi("not a uri at all")["matched"] is False
    assert match_upi("")["matched"] is False


# --- Smart Scanner integration (evidence only) ---


def test_url_scan_with_intel_match():
    envelope = smart_scan_text("https://malicious.example/login")
    assert envelope["input_type"] == "url"
    assert envelope["result"]["threat_intelligence"]["local"]["matched"] is True
    assert envelope["result"]["threat_intelligence"]["external"]["configured"] is False
    # Analyzer verdict is untouched by the intel layer.
    plain = analyze_url("https://malicious.example/login")
    for key in ("score", "risk_level", "category", "reasons", "detected_indicators"):
        assert envelope["result"][key] == plain[key]


def test_url_scan_without_match():
    envelope = smart_scan_text("https://example.com")
    assert envelope["result"]["threat_intelligence"]["local"] == {
        "matched": False, "findings": []}


def test_upi_scan_with_intel_match():
    response = client.post(
        "/api/scan", json={"input": "upi://pay?pa=scammer@demoupi&am=100"})
    assert response.status_code == 200
    body = response.json()
    assert body["result"]["threat_intelligence"]["local"]["matched"] is True
    plain = analyze_upi("upi://pay?pa=scammer@demoupi&am=100")
    assert body["result"]["score"] == plain["score"]
    assert body["result"]["risk_level"] == plain["risk_level"]


def test_url_qr_gets_intel():
    response = client.post(
        "/api/scan",
        files={"file": ("qr.png", make_qr_png("https://scam.example/pay"), "image/png")},
    )
    assert response.status_code == 200
    assert response.json()["result"]["threat_intelligence"]["local"]["matched"] is True


def test_upi_qr_gets_intel():
    response = client.post(
        "/api/scan",
        files={"file": ("qr.png", make_qr_png("upi://pay?pa=scammer@demoupi"), "image/png")},
    )
    assert response.status_code == 200
    assert response.json()["result"]["threat_intelligence"]["local"]["matched"] is True


def test_text_qr_gets_no_intel_field():
    response = client.post(
        "/api/scan", files={"file": ("qr.png", make_qr_png("HELLO"), "image/png")}
    )
    assert response.status_code == 200
    assert "threat_intelligence" not in response.json()["result"]


def test_no_network_requests(monkeypatch):
    import http.client
    import socket

    def blocked(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "gethostbyname", blocked)
    monkeypatch.setattr(http.client.HTTPConnection, "request", blocked)
    assert match_url("https://malicious.example/")["matched"] is True
    assert match_upi("upi://pay?pa=scammer@demoupi")["matched"] is True
    response = client.post("/api/scan", json={"input": "https://scam.example/"})
    assert response.status_code == 200
