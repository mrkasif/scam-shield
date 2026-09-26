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
