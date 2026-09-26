"""API-level tests for POST /api/analyze (no network calls to scanned URLs)."""

import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.index import app

client = TestClient(app)


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_valid_url():
    response = client.post("/api/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["risk_level"] == "GREEN"
    assert body["score"] <= 29


def test_analyze_phishing_url():
    response = client.post(
        "/api/analyze",
        json={"url": "http://paypal-secure-login.evil-example.tk/verify?redirect=x"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["suspicious"] is True
    assert body["reasons"]


def test_analyze_empty_url_rejected():
    response = client.post("/api/analyze", json={"url": "   "})
    assert response.status_code == 422


def test_analyze_bad_scheme_rejected():
    response = client.post("/api/analyze", json={"url": "ftp://example.com/file"})
    assert response.status_code == 422


def test_qr_upload_without_engine_is_clean_503(monkeypatch):
    """Slim hosts (no OpenCV) must answer QR uploads with a clean 503."""
    import scamshield.qr.analyzer as qr_analyzer

    monkeypatch.setattr(qr_analyzer, "_CV2_AVAILABLE", False)
    assert qr_analyzer.qr_engine_available() is False
    response = client.post(
        "/api/analyze/qr",
        files={"file": ("qr.png", b"\x89PNGfakepngdata", "image/png")},
    )
    assert response.status_code == 503
    assert "unavailable" in response.json()["detail"].lower()


def test_link_scan_works_without_engine(monkeypatch):
    """URL scans must be unaffected when OpenCV is missing."""
    import scamshield.qr.analyzer as qr_analyzer

    monkeypatch.setattr(qr_analyzer, "_CV2_AVAILABLE", False)
    response = client.post("/api/scan", json={"input": "https://example.com"})
    assert response.status_code == 200
    assert response.json()["success"] is True
