"""Tests for the URLhaus provider (Step 9). All HTTP is mocked — no real calls."""

import io
import json
import sys
from pathlib import Path

import httpx
import pytest
import qrcode
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from api.index import app  # noqa: E402
from scamshield.analyzer import analyze_url  # noqa: E402
from scamshield.intel.providers import urlhaus  # noqa: E402
from scamshield.intel.providers.urlhaus import (  # noqa: E402
    API_URL,
    check_url,
    sanitize_for_lookup,
)

client = TestClient(app)

TEST_KEY = "test-key-value-that-must-never-leak"


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_URLHAUS_AUTH_KEY", TEST_KEY)
    return TEST_KEY


@pytest.fixture
def unconfigured(monkeypatch):
    monkeypatch.delenv("SCAMSHIELD_URLHAUS_AUTH_KEY", raising=False)


def make_qr_png(data: str) -> bytes:
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


class FakeResponse:
    def __init__(self, status_code=200, payload=None, bad_json=False):
        self.status_code = status_code
        self._payload = payload
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("not json")
        return self._payload


def fake_post_factory(calls, response=None, exc=None):
    def fake_post(url, data=None, headers=None, timeout=None):
        calls.append({"url": url, "data": data, "headers": headers})
        if exc is not None:
            raise exc
        return response

    return fake_post


# --- configuration ---


def test_missing_key_disables_provider(unconfigured, monkeypatch):
    calls: list = []
    monkeypatch.setattr(httpx, "post", fake_post_factory(calls))
    result = check_url("https://example.com/")
    assert result["configured"] is False
    assert result["matched"] is False
    assert calls == []


def test_configured_key_queries_api(configured, monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        httpx, "post",
        fake_post_factory(calls, FakeResponse(200, {"query_status": "no_results"})),
    )
    result = check_url("https://example.com/")
    assert result["configured"] is True
    assert result["available"] is True
    assert result["matched"] is False
    assert len(calls) == 1
    assert calls[0]["url"] == API_URL
    assert calls[0]["headers"] == {"Auth-Key": TEST_KEY}


def test_key_never_in_result(configured, monkeypatch):
    monkeypatch.setattr(
        httpx, "post",
        fake_post_factory([], FakeResponse(200, {"query_status": "no_results"})),
    )
    response = client.post("/api/scan", json={"input": "https://example.com"})
    assert response.status_code == 200
    assert TEST_KEY not in response.text


# --- successful responses ---


def test_match_normalization(configured, monkeypatch):
    calls: list = []
    payload = {
        "query_status": "ok",
        "threat": "malware_download",
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
    }
    monkeypatch.setattr(httpx, "post", fake_post_factory(calls, FakeResponse(200, payload)))
    result = check_url("https://evil.example/payload.exe")
    assert result["matched"] is True
    finding = result["findings"][0]
    assert finding["indicator_type"] == "url"
    assert finding["category"] == "malware"
    assert finding["severity"] == "high"
    assert finding["confidence"] is None
    assert finding["source"] == "URLhaus"


def test_invalid_url_status_is_no_match(configured, monkeypatch):
    monkeypatch.setattr(
        httpx, "post",
        fake_post_factory([], FakeResponse(200, {"query_status": "invalid_url"})),
    )
    result = check_url("https://example.com/")
    assert result["available"] is True
    assert result["matched"] is False


# --- failures stay fail-safe ---


@pytest.mark.parametrize(
    "exc,status,expected",
    [
        (httpx.TimeoutException("t"), 200, "timeout"),
        (httpx.ConnectError("c"), 200, "network_error"),
    ],
)
def test_exception_failures(configured, monkeypatch, exc, status, expected):
    monkeypatch.setattr(httpx, "post", fake_post_factory([], exc=exc))
    result = check_url("https://example.com/")
    assert result == {
        "provider": "urlhaus",
        "configured": True,
        "available": False,
        "matched": False,
        "findings": [],
        "error": expected,
    }


@pytest.mark.parametrize(
    "status,payload,bad_json,expected",
    [
        (429, {}, False, "rate_limited"),
        (500, {}, False, "provider_error"),
        (401, {}, False, "auth_failed"),
        (200, {}, True, "malformed_response"),
        (200, ["not", "a", "dict"], False, "malformed_response"),
        (200, {"query_status": "weird_new_status"}, False, "provider_error"),
        (200, {"query_status": "invalid_auth_key"}, False, "auth_failed"),
    ],
)
def test_response_failures(configured, monkeypatch, status, payload, bad_json, expected):
    monkeypatch.setattr(
        httpx, "post", fake_post_factory([], FakeResponse(status, payload, bad_json))
    )
    result = check_url("https://example.com/")
    assert result["available"] is False
    assert result["matched"] is False
    assert result["error"] == expected


def test_provider_failure_does_not_break_scan(configured, monkeypatch):
    monkeypatch.setattr(
        httpx, "post", fake_post_factory([], exc=httpx.ConnectError("down")))
    response = client.post("/api/scan", json={"input": "https://example.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["result"]["threat_intelligence"]["external"]["available"] is False


# --- privacy: what leaves the machine ---


def test_sanitize_for_lookup():
    sent = sanitize_for_lookup(
        "https://user:pass@Example.COM:8443/a/b?token=secret&x=1#frag"
    )
    assert sent == "https://example.com:8443/a/b?token=...&x=1"
    assert "pass" not in sent and "secret" not in sent and "frag" not in sent


def test_submitted_url_never_fetched(configured, monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        httpx, "post",
        fake_post_factory(calls, FakeResponse(200, {"query_status": "no_results"})),
    )
    submitted = "https://example.com/some/path"
    client.post("/api/scan", json={"input": submitted})
    assert len(calls) == 1  # one lookup per scan, nothing else
    assert calls[0]["url"] == API_URL
    assert calls[0]["data"] == {"url": "https://example.com/some/path"}


# --- integration ---


def test_scan_normal_url_with_provider(configured, monkeypatch):
    monkeypatch.setattr(
        httpx, "post",
        fake_post_factory([], FakeResponse(200, {"query_status": "no_results"})),
    )
    response = client.post("/api/scan", json={"input": "https://example.com"})
    body = response.json()
    assert body["result"]["score"] == analyze_url("https://example.com")["score"]
    assert body["result"]["threat_intelligence"]["external"]["available"] is True


def test_scan_urlhaus_match_leaves_score_unchanged(configured, monkeypatch):
    payload = {"query_status": "ok", "threat": "malware_download"}
    monkeypatch.setattr(httpx, "post", fake_post_factory([], FakeResponse(200, payload)))
    url = "https://example.com/malware.exe"
    body = client.post("/api/scan", json={"input": url}).json()
    assert body["result"]["threat_intelligence"]["external"]["matched"] is True
    assert body["result"]["score"] == analyze_url(url)["score"]
    assert body["result"]["risk_level"] == analyze_url(url)["risk_level"]


def test_scan_local_intel_url_with_provider(configured, monkeypatch):
    monkeypatch.setattr(
        httpx, "post",
        fake_post_factory([], FakeResponse(200, {"query_status": "no_results"})),
    )
    body = client.post("/api/scan", json={"input": "https://scam.example/"}).json()
    assert body["result"]["threat_intelligence"]["local"]["matched"] is True
    assert body["result"]["threat_intelligence"]["external"]["matched"] is False


def test_url_qr_triggers_one_lookup(configured, monkeypatch):
    calls: list = []
    monkeypatch.setattr(
        httpx, "post",
        fake_post_factory(calls, FakeResponse(200, {"query_status": "no_results"})),
    )
    response = client.post(
        "/api/scan",
        files={"file": ("qr.png", make_qr_png("https://example.com"), "image/png")},
    )
    assert response.status_code == 200
    assert len(calls) == 1


def test_upi_qr_sends_nothing_externally(configured, monkeypatch):
    calls: list = []
    monkeypatch.setattr(httpx, "post", fake_post_factory(calls))
    uri = "upi://pay?pa=shop@paytm&am=100"
    response = client.post(
        "/api/scan", files={"file": ("qr.png", make_qr_png(uri), "image/png")}
    )
    assert response.status_code == 200
    assert calls == []
    assert "external" not in response.json()["result"]["threat_intelligence"]


def test_text_qr_sends_nothing_externally(configured, monkeypatch):
    calls: list = []
    monkeypatch.setattr(httpx, "post", fake_post_factory(calls))
    response = client.post(
        "/api/scan", files={"file": ("qr.png", make_qr_png("HELLO"), "image/png")}
    )
    assert response.status_code == 200
    assert calls == []
