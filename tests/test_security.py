"""Security regression tests: input limits, safe errors, upload safety, XSS.

These pin the hardening contract without changing detection behavior.
"""

import io
import json
import sys
from pathlib import Path

import qrcode
from fastapi.testclient import TestClient
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.index import app  # noqa: E402

client = TestClient(app, raise_server_exceptions=False)

XSS_TEXT = "<script>alert(1)</script>"
XSS_IMG = '<img src=x onerror="alert(1)">'


def make_qr_png(data: str) -> bytes:
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def assert_clean_error(response, statuses=(400, 404, 413, 415, 422)):
    assert response.status_code in statuses
    body = response.json()
    assert isinstance(body.get("detail"), str)
    text = json.dumps(body)
    assert "Traceback" not in text
    assert ".py" not in text


# --- oversized / malformed text input ---


def test_oversized_url_rejected():
    big = "https://example.com/" + "a" * 5000
    for path, key in (
        ("/api/analyze", "url"),
        ("/api/analyze/upi", "upi_uri"),
        ("/api/scan", "input"),
    ):
        response = client.post(path, json={key: big})
        assert response.status_code in (413, 422), path


def test_oversized_json_body_rejected():
    huge = "https://example.com/?q=" + "a" * (2 * 1024 * 1024)
    response = client.post("/api/analyze", json={"url": huge})
    assert response.status_code == 413
    assert isinstance(response.json()["detail"], str)


def test_malformed_json_rejected():
    response = client.post(
        "/api/analyze", content=b'{"url": ', headers={"Content-Type": "application/json"}
    )
    assert response.status_code in (400, 422)
    body = response.json()
    assert "detail" in body  # FastAPI list-form validation error, no leakage
    assert "Traceback" not in json.dumps(body)


def test_wrong_content_type_rejected():
    response = client.post(
        "/api/analyze", content="https://example.com", headers={"Content-Type": "text/plain"}
    )
    assert response.status_code == 415


# --- upload safety ---


def test_oversized_qr_upload_rejected():
    big = b"\x89PNG" + b"\x00" * (11 * 1024 * 1024)
    for path in ("/api/analyze/qr", "/api/scan"):
        response = client.post(
            path, files={"file": ("qr.png", big, "image/png")}
        )
        assert response.status_code == 413, path


def test_malformed_qr_image_clean_error():
    response = client.post(
        "/api/analyze/qr",
        files={"file": ("qr.png", b"\x00\x01not-an-image", "image/png")},
    )
    assert_clean_error(response, (422,))


def test_decompression_dimensions_capped():
    """A tiny file claiming huge dimensions must fail safely, not allocate."""
    import cv2
    import numpy as np

    tiny = np.zeros((2, 2, 3), dtype=np.uint8)
    ok, buf = cv2.imencode(".png", tiny)
    assert ok
    data = buf.tobytes()
    # Lie about dimensions in the IHDR chunk (width/height = 20000).
    import struct

    width_pos = data.index(b"IHDR") + 4
    forged = data[:width_pos] + struct.pack(">II", 20000, 20000) + data[width_pos + 8 :]
    response = client.post(
        "/api/analyze/qr", files={"file": ("qr.png", forged, "image/png")}
    )
    # Either rejected as too large or as undecodable — never a crash/leak.
    assert response.status_code in (413, 422)
    assert_clean_error(response, (422,))


# --- malicious payloads stay inert data ---


def test_xss_text_qr_returned_as_json_data():
    response = client.post(
        "/api/analyze/qr",
        files={"file": ("qr.png", make_qr_png(XSS_TEXT), "image/png")},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["payload"] == XSS_TEXT


def test_xss_text_scan_returned_as_json_data():
    response = client.post("/api/scan", json={"input": XSS_IMG})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["result"]["content"] == XSS_IMG


def test_frontend_uses_safe_dom_apis():
    """All dynamic DOM writes must use textContent (never HTML sinks)."""
    source = (Path(__file__).resolve().parent.parent / "public" / "app.js").read_text(
        encoding="utf-8"
    )
    for dangerous in ("eval(", "document.write", "outerHTML", "insertAdjacentHTML"):
        assert dangerous not in source, dangerous
    for line in source.splitlines():
        stripped = line.strip()
        if "innerHTML" in stripped:
            assert stripped.endswith('.innerHTML = "";'), stripped


def test_error_responses_are_clean():
    for response in (
        client.post("/api/analyze", json={"url": "   "}),
        client.post("/api/analyze/upi", json={"upi_uri": "nope"}),
        client.post("/api/scan", json={"input": "mailto:a@b.com"}),
        client.get("/api/does-not-exist"),
    ):
        assert_clean_error(response, (400, 404, 413, 415, 422))


def test_security_headers_present():
    response = client.get("/")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "SAMEORIGIN"
    assert response.headers["referrer-policy"] == "no-referrer"
    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "blob:" in csp  # required for the QR preview
    assert "font-src https://fonts.gstatic.com" in csp
    assert "https://fonts.googleapis.com" in csp
    api = client.get("/api/health")
    assert api.headers["x-content-type-options"] == "nosniff"


def test_cors_not_wildcard_by_default():
    response = client.options(
        "/api/analyze",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert "evil.example" not in response.headers.get("access-control-allow-origin", "")


# --- prior functionality intact ---


def test_valid_url_still_works():
    response = client.post("/api/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.json()["risk_level"] == "GREEN"


def test_valid_upi_still_works():
    response = client.post(
        "/api/analyze/upi", json={"upi_uri": "upi://pay?pa=shop@paytm&am=100"}
    )
    assert response.status_code == 200
    assert response.json()["risk_level"] == "GREEN"


def test_valid_qr_still_works():
    response = client.post(
        "/api/analyze/qr",
        files={"file": ("qr.png", make_qr_png("https://example.com"), "image/png")},
    )
    assert response.status_code == 200
    assert response.json()["type"] == "url"


def test_vercel_config_valid():
    config = json.loads(
        (Path(__file__).resolve().parent.parent / "vercel.json").read_text(
            encoding="utf-8"
        )
    )
    assert config["outputDirectory"] == "public"
    assert any("api" in str(r) for r in config["rewrites"])
