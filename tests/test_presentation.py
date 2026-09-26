"""Tests for demo presentation (Step 12). No detection behavior asserted."""

import json
import re
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.index import app  # noqa: E402

client = TestClient(app)
ROOT = Path(__file__).resolve().parent.parent


def test_status_endpoint_shape():
    response = client.get("/api/status")
    assert response.status_code == 200
    body = response.json()
    assert body["scanner"] == "ready"
    assert body["qr_engine"] in ("ready", "unavailable")
    assert body["local_intelligence"] == "ready"
    assert body["local_indicators"] == 5
    assert body["external_intelligence"] in ("configured", "not_configured")
    assert body["evaluation_cases"] == 128


def test_status_leaks_no_secret(monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_URLHAUS_AUTH_KEY", "super-secret-test-key-xyz")
    body = client.get("/api/status").text
    assert "super-secret-test-key-xyz" not in body
    assert "SCAMSHIELD_URLHAUS_AUTH_KEY" not in body


def test_nav_anchors_resolve():
    html = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
    anchors = re.findall(r'href="#([^"]+)"', html)
    assert len(anchors) >= 4
    for anchor in anchors:
        assert re.search(r'id="%s"' % re.escape(anchor), html), anchor
    for section in ("sec-scanner", "sec-dashboard",
                    "sec-eval", "sec-url", "sec-qr", "sec-upi", "sys-status"):
        assert f'id="{section}"' in html, section


def test_evaluation_figures_match_report():
    metrics = json.loads((ROOT / "evaluation" / "results.json").read_text(
        encoding="utf-8"))
    html = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
    assert metrics["summary"]["cases"] == 128
    for figure in ("128", "104/128", "58.5%", "93.9%", "58.5%", "2.7%"):
        assert figure in html, figure
    for value in ("31", "72"):
        assert f"<dd>{value}</dd>" in html, value
    assert "<dd>2</dd>" in html and "<dd>22</dd>" in html and "<dd>0</dd>" in html
    assert "80% accuracy" not in html


def test_no_inline_handlers_or_alerts():
    html = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"\son\w+\s*=", html)
    assert "<script src=" in html and html.count("<script") == 1
    js = (ROOT / "public" / "app.js").read_text(encoding="utf-8")
    assert "alert(" not in js
    assert "sys-status" in js and "/api/status" in js


def test_theme_toggle_and_light_roles():
    html = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
    assert 'id="theme-toggle"' in html
    css = (ROOT / "public" / "style.css").read_text(encoding="utf-8")
    for role in ("--bg0", "--bg1", "--bg2", "--line", "--ink", "--mut",
                 "--acc", "--ok", "--warn", "--bad"):
        assert role in css, role
    light = css[css.index('[data-theme="light"]'):]
    for role in ("--bg0", "--bg1", "--bg2", "--line", "--ink", "--mut",
                 "--acc", "--ok", "--warn", "--bad"):
        assert role in light, role
    js = (ROOT / "public" / "app.js").read_text(encoding="utf-8")
    assert "scamshield-theme" in js and "prefers-color-scheme" in js
    assert "localStorage" in js


def test_theme_toggle_and_light_roles():
    html = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
    assert 'id="theme-toggle"' in html
    css = (ROOT / "public" / "style.css").read_text(encoding="utf-8")
    for role in ("--bg0", "--bg1", "--bg2", "--line", "--ink", "--mut",
                 "--acc", "--ok", "--warn", "--bad"):
        assert role in css, role
    light = css[css.index('[data-theme="light"]'):]
    for role in ("--bg0", "--bg1", "--bg2", "--line", "--ink", "--mut",
                 "--acc", "--ok", "--warn", "--bad"):
        assert role in light, role
    js = (ROOT / "public" / "app.js").read_text(encoding="utf-8")
    assert "scamshield-theme" in js and "prefers-color-scheme" in js
    assert "localStorage" in js
