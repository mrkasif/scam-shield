"""Tests for the ScamShield UPI analyzer (Step 4, static only, no network)."""

import io
import sys
from pathlib import Path

import qrcode
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from api.index import app  # noqa: E402
from scamshield.scoring import risk_level  # noqa: E402
from scamshield.upi import analyze_upi  # noqa: E402

client = TestClient(app)

VALID = "upi://pay?pa=merchant@okhdfc&pn=Merchant%20Name&am=999&cu=INR&tn=Payment"


def make_qr_png(data: str) -> bytes:
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_valid_normal_upi_uri_is_green():
    result = analyze_upi(VALID)
    assert result["type"] == "upi"
    assert result["risk_level"] == "GREEN"
    assert result["suspicious"] is False
    assert result["components"]["pa"] == "merchant@okhdfc"
    assert result["components"]["am"] == "999"
    assert result["components"]["cu"] == "INR"


def test_missing_pa_flagged():
    result = analyze_upi("upi://pay?pn=Someone&am=100")
    assert "missing_pa" in result["detected_indicators"]
    assert result["suspicious"] is True


def test_malformed_upi_id_flagged():
    result = analyze_upi("upi://pay?pa=not-a-valid-id&am=100")
    assert "malformed_pa" in result["detected_indicators"]
    assert result["suspicious"] is True


def test_valid_amount_not_penalized():
    result = analyze_upi("upi://pay?pa=shop@paytm&am=250.50")
    assert "bad_amount" not in result["detected_indicators"]
    assert "high_amount" not in result["detected_indicators"]


def test_suspicious_amount_formatting():
    result = analyze_upi("upi://pay?pa=shop@paytm&am=12abc")
    assert "bad_amount" in result["detected_indicators"]


def test_suspicious_payment_note_urgency():
    result = analyze_upi("upi://pay?pa=shop@paytm&tn=Pay%20immediately%20or%20account%20blocked")
    assert "urgency_language" in result["detected_indicators"]
    assert result["score"] > 0
    assert result["reasons"]


def test_kyc_language_flagged():
    result = analyze_upi("upi://pay?pa=x@ybl&tn=Complete%20KYC%20verification%20now")
    assert "kyc_language" in result["detected_indicators"]
    assert result["suspicious"] is True


def test_reward_language_flagged():
    result = analyze_upi("upi://pay?pa=x@ybl&tn=You%20won%20a%20prize%20claim%20refund")
    assert "reward_language" in result["detected_indicators"]
    assert result["suspicious"] is True


def test_missing_optional_parameters_ok():
    result = analyze_upi("upi://pay?pa=shop@paytm")
    assert result["risk_level"] == "GREEN"
    assert result["components"]["am"] is None


def test_unknown_parameters_noted():
    result = analyze_upi("upi://pay?pa=shop@paytm&foo=1&zzz=2")
    assert "unknown_params" in result["detected_indicators"]


def test_url_qr_still_uses_url_analyzer():
    response = client.post(
        "/api/analyze/qr", files={"file": ("qr.png", make_qr_png("https://example.com"), "image/png")}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "url"
    assert body["analysis"]["risk_level"] == "GREEN"


def test_upi_qr_receives_upi_analysis():
    uri = "upi://pay?pa=shop@paytm&pn=Shop&am=100&cu=INR"
    response = client.post(
        "/api/analyze/qr", files={"file": ("qr.png", make_qr_png(uri), "image/png")}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "upi"
    assert body["analysis"]["type"] == "upi"
    assert body["analysis"]["components"]["pa"] == "shop@paytm"
    assert body["analysis"] == analyze_upi(uri)


def test_plain_text_qr_still_text():
    response = client.post(
        "/api/analyze/qr", files={"file": ("qr.png", make_qr_png("HELLO"), "image/png")}
    )
    assert response.status_code == 200
    assert response.json()["type"] == "text"


def test_no_network_requests(monkeypatch):
    import http.client
    import socket

    def blocked(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "gethostbyname", blocked)
    monkeypatch.setattr(http.client.HTTPConnection, "request", blocked)
    result = analyze_upi(VALID)
    assert result["risk_level"] == "GREEN"
    response = client.post("/api/analyze/upi", json={"upi_uri": VALID})
    assert response.status_code == 200


def test_api_validation_errors():
    assert client.post("/api/analyze/upi", json={"upi_uri": "   "}).status_code == 422
    assert client.post("/api/analyze/upi", json={"upi_uri": "https://example.com"}).status_code == 422
    response = client.post("/api/analyze/upi", json={"upi_uri": VALID})
    assert response.status_code == 200
    assert response.json()["type"] == "upi"


def test_comma_in_note_not_obfuscation():
    result = analyze_upi("upi://pay?pa=shop@paytm&tn=Thanks%2C+see+you+soon")
    assert "obfuscated_content" not in result["detected_indicators"]


def test_risk_score_boundaries():
    assert risk_level(0) == "GREEN"
    assert risk_level(29) == "GREEN"
    assert risk_level(30) == "YELLOW"
    assert risk_level(69) == "YELLOW"
    assert risk_level(70) == "RED"
    worst = analyze_upi(
        "upi://pay?pa=bad%20id%20here&pn=RBI%20KYC%20Officer&am=-50&cu=USD"
        "&tn=Urgent%20prize%20refund%20verify%20immediately%20blocked"
        "&x1=1&x2=2&x3=3&x4=4&x5=5&x6=6&x7=7&x8=8&x9=9&x10=1&x11=2"
    )
    assert 0 <= worst["score"] <= 100
    assert worst["risk_level"] == "RED"
