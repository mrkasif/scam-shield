"""Tests for scan history + dashboard backend (Step 7, metadata only)."""

import io
import sys
from pathlib import Path

import qrcode
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import api.index as api_module  # noqa: E402
from api.index import app  # noqa: E402
from scamshield.history import (  # noqa: E402
    HistoryStore,
    build_record,
    sanitize_upi_preview,
    sanitize_url_preview,
)

client = TestClient(app)


def make_qr_png(data: str) -> bytes:
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def fresh_store(tmp_path) -> HistoryStore:
    return HistoryStore(tmp_path / "history.db")


def test_history_creation_and_retrieval(tmp_path):
    store = fresh_store(tmp_path)
    entry = store.record(
        {"input_type": "url", "success": True,
         "result": {"normalized_url": "https://example.com",
                    "score": 0, "risk_level": "GREEN", "category": "benign",
                    "suspicious": False}}
    )
    assert entry["id"] and entry["ts"]
    scans = store.list()
    assert len(scans) == 1
    assert scans[0]["preview"] == "https://example.com"
    assert scans[0]["suspicious"] is False


def test_newest_first_ordering(tmp_path):
    store = fresh_store(tmp_path)
    for url in ("https://a.example", "https://b.example"):
        store.record(
            {"input_type": "url", "success": True,
             "result": {"normalized_url": url, "score": 0,
                        "risk_level": "GREEN", "category": "benign",
                        "suspicious": False}}
        )
    scans = store.list(limit=10)
    assert [s["preview"] for s in scans] == ["https://b.example", "https://a.example"]


def test_statistics(tmp_path):
    store = fresh_store(tmp_path)
    store.record({"input_type": "url", "success": True,
                  "result": {"score": 0, "risk_level": "GREEN",
                             "category": "benign", "suspicious": False}})
    store.record({"input_type": "upi", "success": True,
                  "result": {"score": 80, "risk_level": "RED",
                             "category": "reward_lure", "suspicious": True}})
    stats = store.stats()
    assert stats["total"] == 2
    assert stats["green"] == 1 and stats["red"] == 1 and stats["yellow"] == 0
    assert stats["suspicious"] == 1
    assert stats["by_type"]["url"] == 1 and stats["by_type"]["upi"] == 1
    assert stats["categories"] == {"benign": 1, "reward_lure": 1}


def test_clear_history(tmp_path):
    store = fresh_store(tmp_path)
    store.record({"input_type": "text", "success": True,
                  "result": {"content": "hi"}})
    assert store.clear() == 1
    assert store.list() == []
    assert store.stats()["total"] == 0


def test_sanitized_url_storage():
    preview = sanitize_url_preview(
        "https://user:pass@Example.COM:8443/a/b?token=secret&redirect=evil.com#frag"
    )
    assert "user" not in preview and "pass" not in preview
    assert "secret" not in preview and "#frag" not in preview
    assert "example.com" in preview and "/a/b" in preview
    assert "token=" in preview and "redirect=" in preview


def test_sanitized_upi_storage():
    preview = sanitize_upi_preview(
        "upi://pay?pa=shop@paytm&pn=My%20Shop&am=100&tn=thanks&tr=REF123"
    )
    assert preview.startswith("upi://pay?pa=")
    assert "@paytm" in preview and "am=100" in preview
    assert "My Shop" not in preview and "thanks" not in preview
    assert "REF123" not in preview and "shop@paytm" not in preview


def test_empty_history_api():
    client.delete("/api/history")
    assert client.get("/api/history").json() == {
        "scans": [], "persistent": api_module.history_store.persistent}
    stats = client.get("/api/history/stats").json()
    assert stats["total"] == 0 and stats["by_type"] == {
        "url": 0, "qr": 0, "upi": 0, "text": 0}


def test_scan_records_history_api():
    client.delete("/api/history")
    scan = client.post("/api/scan", json={"input": "https://example.com"})
    assert scan.status_code == 200
    history = client.get("/api/history").json()
    assert len(history["scans"]) == 1
    assert history["scans"][0]["input_type"] == "url"
    stats = client.get("/api/history/stats").json()
    assert stats["total"] == 1 and stats["green"] == 1
    cleared = client.delete("/api/history").json()
    assert cleared == {"cleared": 1}
    assert client.get("/api/history").json()["scans"] == []


def test_qr_upi_scan_records_sanitized_api():
    client.delete("/api/history")
    uri = "upi://pay?pa=shop@paytm&pn=Secret%20Name&am=100&tn=hidden-note"
    response = client.post(
        "/api/scan", files={"file": ("qr.png", make_qr_png(uri), "image/png")})
    assert response.status_code == 200
    preview = client.get("/api/history").json()["scans"][0]["preview"]
    assert "Secret" not in preview and "hidden-note" not in preview
    assert "@paytm" in preview
    client.delete("/api/history")


def test_history_failure_does_not_break_scan(monkeypatch):
    def boom(envelope):
        raise RuntimeError("disk gone")

    monkeypatch.setattr(api_module.history_store, "record", boom)
    response = client.post("/api/scan", json={"input": "https://example.com"})
    assert response.status_code == 200
    assert response.json()["success"] is True


def test_existing_endpoints_regression():
    assert client.get("/api/health").status_code == 200
    assert client.post("/api/analyze", json={"url": "https://example.com"}).status_code == 200
    assert client.post(
        "/api/analyze/upi", json={"upi_uri": "upi://pay?pa=a@b"}).status_code == 200
    assert client.post(
        "/api/analyze/qr",
        files={"file": ("qr.png", make_qr_png("https://example.com"), "image/png")},
    ).status_code == 200


def test_vercel_mode_is_memory_and_graceful(monkeypatch):
    """On Vercel (VERCEL=1) the store must never touch the filesystem:
    empty history, not a hard error."""
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("SCAMSHIELD_HISTORY_DB", raising=False)
    store = HistoryStore("data/scamshield_history.db")
    assert store.persistent is False
    assert store.list() == []
    stats = store.stats()
    assert stats["total"] == 0
    entry = store.record(
        {"input_type": "url", "success": True,
         "result": {"normalized_url": "https://example.com",
                    "score": 0, "risk_level": "GREEN", "category": "benign",
                    "suspicious": False}}
    )
    assert entry["id"]
    assert store.stats()["total"] == 1
