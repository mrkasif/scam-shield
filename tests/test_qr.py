"""Tests for the ScamShield QR scanner (Step 2).

QR fixture images are generated in-memory with the ``qrcode`` library —
no external files required.
"""

import io
import sys
from pathlib import Path

import qrcode
from fastapi.testclient import TestClient
from PIL import Image

import pytest

cv2 = pytest.importorskip("cv2", reason="QR decode tests need OpenCV")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from api.index import app  # noqa: E402
from scamshield.analyzer import analyze_url  # noqa: E402
from scamshield.qr.analyzer import (  # noqa: E402
    analyze_qr_image,
    classify_payload,
    decode_qr_image,
)

client = TestClient(app)


def make_qr_png(data: str) -> bytes:
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def make_blank_png(size: int = 200) -> bytes:
    img = Image.new("RGB", (size, size), color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def post_qr(image_bytes: bytes, filename: str = "qr.png"):
    return client.post(
        "/api/analyze/qr",
        files={"file": (filename, image_bytes, "image/png")},
    )


# --- unit: decode / classify ---


def test_decode_unit_returns_payload():
    payload = decode_qr_image(make_qr_png("https://example.com"))
    assert payload == "https://example.com"


def test_decode_unit_blank_image_returns_none():
    assert decode_qr_image(make_blank_png()) is None


def test_classify_empty_payload():
    result = classify_payload("   ")
    assert result["type"] == "empty"


def test_classify_unknown_scheme():
    result = classify_payload("mailto:someone@example.com")
    assert result["type"] == "unknown"


# --- API: URL QRs ---


def test_valid_url_qr():
    response = post_qr(make_qr_png("https://example.com"))
    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "url"
    assert body["payload"] == "https://example.com"
    assert body["analysis"]["risk_level"] == "GREEN"
    assert "NOT been opened" in body["note"] or "NOT opened" in body["note"]


def test_malicious_url_qr():
    evil = "http://paypal-secure-login-verify.evil-example.tk/login?redirect=x"
    response = post_qr(make_qr_png(evil))
    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "url"
    assert body["analysis"]["suspicious"] is True
    assert body["analysis"]["reasons"]


def test_qr_url_reaches_existing_analyzer():
    """The QR endpoint must reuse the Step 1 analyzer verdict verbatim."""
    url = "http://192.168.1.10/login?token=abc"
    response = post_qr(make_qr_png(url))
    assert response.status_code == 200
    assert response.json()["analysis"] == analyze_url(url)


# --- API: non-URL payloads (must not pretend to be safe) ---


def test_plain_text_qr():
    response = post_qr(make_qr_png("HELLO SCAMSHIELD"))
    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "text"
    assert body["payload"] == "HELLO SCAMSHIELD"
    assert "analysis" not in body
    assert body["note"]


def test_upi_qr():
    upi = "upi://pay?pa=shop@upi&pn=Shop&am=100&cu=INR&tn=test"
    response = post_qr(make_qr_png(upi))
    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "upi"
    assert body["payload"] == upi
    # Step 4: QR UPI payloads now carry the full UPI analysis.
    assert body["analysis"]["type"] == "upi"
    assert body["analysis"]["components"]["pa"] == "shop@upi"
    assert body["upi_details"]["payee address"] == "shop@upi"
    assert body["upi_details"]["amount"] == "100"


# --- API: invalid inputs rejected cleanly ---


def test_unreadable_image_rejected():
    response = post_qr(make_blank_png())
    assert response.status_code == 422
    assert "No QR code" in response.json()["detail"]


def test_missing_image_rejected():
    response = client.post("/api/analyze/qr")
    assert response.status_code == 422


def test_malformed_image_rejected():
    response = client.post(
        "/api/analyze/qr",
        files={"file": ("qr.png", b"\x00\x01\x02not-an-image", "image/png")},
    )
    assert response.status_code == 422


def test_non_image_content_type_rejected():
    response = client.post(
        "/api/analyze/qr",
        files={"file": ("note.txt", b"hello", "text/plain")},
    )
    assert response.status_code == 422
