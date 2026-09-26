"""Tests for the unified Smart Scanner (Step 5).

The facade routes to the existing analyzers; these tests pin the routing
contract and the /api/scan envelope without re-testing detection rules.
"""

import io
import sys
from pathlib import Path

import pytest
import qrcode
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from api.index import app  # noqa: E402
from scamshield.analyzer import (  # noqa: E402
    analyze_url,
    detect_input_type,
    smart_scan_text,
)

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


def test_detect_input_type_routing():
    assert detect_input_type("https://example.com/login") == "url"
    assert detect_input_type("example.com/login") == "url"
    assert detect_input_type("upi://pay?pa=merchant@bank&am=500") == "upi"
    assert detect_input_type("UPI://pay?pa=a@b") == "upi"
    assert detect_input_type("hello world") == "text"
    assert detect_input_type("mailto:a@b.com") == "unknown"
    assert detect_input_type("ftp://example.com/f") == "unknown"
    assert detect_input_type("   ") == "unknown"


def test_unified_url_scan():
    envelope = smart_scan_text("https://example.com")
    expected_result = analyze_url("https://example.com")
    expected_result["threat_intelligence"] = {
        "local": {"matched": False, "findings": []},
        "external": {
            "provider": "urlhaus",
            "configured": False,
            "available": False,
            "matched": False,
            "findings": [],
            "error": None,
        },
    }
    assert envelope == {
        "input_type": "url",
        "success": True,
        "result": expected_result,
    }
    response = client.post("/api/scan", json={"input": "https://example.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["input_type"] == "url"
    assert body["success"] is True
    assert body["result"]["risk_level"] == "GREEN"


def test_unified_upi_scan():
    uri = "upi://pay?pa=merchant@bank&am=500"
    response = client.post("/api/scan", json={"input": uri})
    assert response.status_code == 200
    body = response.json()
    assert body["input_type"] == "upi"
    assert body["success"] is True
    assert body["result"]["type"] == "upi"
    assert body["result"]["components"]["pa"] == "merchant@bank"


def test_unified_qr_url():
    response = client.post(
        "/api/scan",
        files={"file": ("qr.png", make_qr_png("https://example.com"), "image/png")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "input_type": "qr",
        "success": True,
        "result": {
            "type": "url",
            "payload": "https://example.com",
            "analysis": analyze_url("https://example.com"),
            "threat_intelligence": {
                "local": {"matched": False, "findings": []},
                "external": {
                    "provider": "urlhaus",
                    "configured": False,
                    "available": False,
                    "matched": False,
                    "findings": [],
                    "error": None,
                },
            },
            "note": body["result"]["note"],
        },
    }


def test_unified_qr_upi():
    uri = "upi://pay?pa=shop@paytm&am=100"
    response = client.post(
        "/api/scan", files={"file": ("qr.png", make_qr_png(uri), "image/png")}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["input_type"] == "qr"
    assert body["result"]["type"] == "upi"
    assert body["result"]["analysis"]["type"] == "upi"
    assert body["result"]["analysis"]["components"]["pa"] == "shop@paytm"


def test_unified_qr_text():
    response = client.post(
        "/api/scan", files={"file": ("qr.png", make_qr_png("HELLO"), "image/png")}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["input_type"] == "qr"
    assert body["result"]["type"] == "text"


def test_unknown_input_rejected():
    response = client.post("/api/scan", json={"input": "mailto:a@b.com"})
    assert response.status_code == 422


def test_empty_input_rejected():
    assert client.post("/api/scan", json={"input": "   "}).status_code == 422
    try:
        smart_scan_text("  ")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_invalid_input_rejected():
    assert client.post("/api/scan", json={"input": "http://"}).status_code == 422
    assert client.post("/api/scan", json={"input": "upi://"}).status_code == 422
    assert client.post("/api/scan", json={}).status_code == 422


def test_qr_error_handling():
    # Missing file part.
    assert client.post("/api/scan", files={}).status_code == 422
    # Malformed image bytes.
    bad = client.post(
        "/api/scan", files={"file": ("qr.png", b"\x00not-an-image", "image/png")}
    )
    assert bad.status_code == 422
    # Non-image upload.
    txt = client.post(
        "/api/scan", files={"file": ("n.txt", b"hello", "text/plain")}
    )
    assert txt.status_code == 422


def test_existing_endpoints_unchanged():
    assert client.get("/api/health").status_code == 200
    assert client.post("/api/analyze", json={"url": "https://example.com"}).status_code == 200
    assert client.post(
        "/api/analyze/qr",
        files={"file": ("qr.png", make_qr_png("https://example.com"), "image/png")},
    ).status_code == 200
    assert client.post(
        "/api/analyze/upi", json={"upi_uri": "upi://pay?pa=a@b"}
    ).status_code == 200
