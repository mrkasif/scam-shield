"""Tests for the evaluation lab (Steps 10–11). Never touches production rules."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from scamshield.evaluation import (  # noqa: E402
    CASES,
    EVALUATOR_VERSION,
    EvaluationCase,
    evaluate,
    generate_reports,
    load_cases,
    run_all,
    run_case,
)
from scamshield.evaluation.__main__ import main as eval_main  # noqa: E402
from scamshield.evaluation.report import build_markdown, build_payload  # noqa: E402


def _by_id(cid):
    return next(c for c in CASES if c.id == cid)


def test_corpus_loads_with_unique_ids():
    cases = load_cases()
    assert 100 <= len(cases) <= 140
    ids = [c.id for c in cases]
    assert len(ids) == len(set(ids))
    types = {c.input_type for c in cases}
    assert {"url", "upi", "qr_url", "qr_upi", "qr_text", "qr_bad"} <= types


def test_case_schema_validation():
    for case in CASES:
        case.validate()
    bad = EvaluationCase("x", "n", "url", "https://example.com", "NOPE",
                         "benign", "low", "d")
    try:
        bad.validate()
    except AssertionError:
        pass
    else:
        raise AssertionError("expected AssertionError")


def test_url_cases_run():
    assert run_case(_by_id("u01"))["passed"] is True
    assert run_case(_by_id("u07"))["passed"] is True
    assert run_case(_by_id("u07"))["actual_class"] == "SUSPICIOUS"


def test_upi_cases_run():
    assert run_case(_by_id("p01"))["passed"] is True
    assert run_case(_by_id("p05"))["passed"] is True
    assert run_case(_by_id("p05"))["actual_category"] == "invalid_payee"


def test_qr_cases_run_through_real_decoder():
    assert run_case(_by_id("q01"))["passed"] is True
    assert run_case(_by_id("q04"))["passed"] is True
    assert run_case(_by_id("q05"))["actual_class"] == "SAFE"
    bad = run_case(_by_id("q06"))
    assert bad["actual_class"] == "DECODE_ERROR"
    assert bad["passed"] is True


def test_classification_mapping():
    assert run_case(_by_id("u21"))["actual_class"] == "HIGH_RISK"
    assert run_case(_by_id("u01"))["actual_class"] == "SAFE"


def _synthetic_results():
    def row(exp, act):
        return {"expected_class": exp, "actual_class": act, "passed": exp == act,
                "expected_category": "c", "actual_category": "c",
                "risk_level": None, "score": None, "reasons": [],
                "detected_indicators": [], "explainability": None, "error": None}

    return [row("SUSPICIOUS", "SUSPICIOUS"), row("HIGH_RISK", "SAFE"),
            row("SAFE", "SAFE"), row("SAFE", "SUSPICIOUS")]


def test_metric_calculations():
    metrics = evaluate(_synthetic_results())
    assert (metrics["true_positives"], metrics["true_negatives"],
            metrics["false_positives"], metrics["false_negatives"]) == (1, 1, 1, 1)
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["detection_rate"] == 0.5
    assert metrics["false_positive_rate"] == 0.5


def test_metric_zero_division_safe():
    metrics = evaluate([])
    assert metrics["total"] == 0
    assert metrics["precision"] == 0.0 and metrics["recall"] == 0.0
    assert metrics["false_positive_rate"] == 0.0


def test_explainability_flagged():
    assert run_case(_by_id("u22"))["explainability"] is True
    assert run_case(_by_id("u01"))["explainability"] is None


def test_report_generation(tmp_path):
    results = run_all([_by_id("u01"), _by_id("u07")])
    metrics = evaluate(results)
    paths = generate_reports(results, metrics, "0.1.0", tmp_path)
    results_json = Path(paths["results_json"])
    report_md = Path(paths["report_md"])
    assert results_json.exists() and report_md.exists()
    import json

    payload = json.loads(results_json.read_text(encoding="utf-8"))
    assert payload["summary"]["cases"] == 2
    assert "limitations" in payload
    text = report_md.read_text(encoding="utf-8")
    assert "## 8. Category-wise results" in text
    assert "## 14. Limitations" in text
    assert "## 16. Honest conclusion" in text


def test_deterministic_repeated_runs():
    first = run_all(load_cases())
    second = run_all(load_cases())
    assert first == second


def test_no_network_behavior(monkeypatch):
    import http.client
    import socket

    import httpx

    def blocked(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "gethostbyname", blocked)
    monkeypatch.setattr(http.client.HTTPConnection, "request", blocked)
    monkeypatch.setattr(httpx, "post", blocked)
    results = run_all(load_cases())
    assert len(results) == len(CASES)
    assert all(r["error"] is None or "UNEXPECTED" not in (r["error"] or "") for r in results)


def _payload():
    results = run_all(load_cases())
    metrics = evaluate(results)
    metadata = {
        "evaluator_version": EVALUATOR_VERSION,
        "deterministic_runs": True,
        "network_disabled_runs": True,
        "python_version": "3.14.0",
        "packages": {"pytest": "8.0.0"},
    }
    return results, build_payload(results, metrics, "0.1.0", metadata)


def test_results_schema_and_confusion_consistency():
    results, payload = _payload()
    assert set(payload["confusion_matrix"]) == {
        "positive_class", "predicted_positive", "true_positives",
        "false_negatives", "false_positives", "true_negatives",
    }
    cm = payload["confusion_matrix"]
    threat = sum(1 for r in results if r["expected_class"] in ("SUSPICIOUS", "HIGH_RISK"))
    safe = sum(1 for r in results if r["expected_class"] == "SAFE")
    assert cm["true_positives"] + cm["false_negatives"] == threat
    assert cm["true_negatives"] + cm["false_positives"] == safe
    dm = payload["detection_metrics"]
    assert dm["detection_rate"] == dm["recall"]
    assert dm["precision"] == cm["true_positives"] / (cm["true_positives"] + cm["false_positives"])
    assert payload["metadata"]["case_count"] == len(results)
    dist = payload["metadata"]["case_distribution"]
    assert sum(dist["by_input_type"].values()) == len(results)
    assert sum(dist["by_expected_class"].values()) == len(results)


def test_report_contains_all_sections():
    _, payload = _payload()
    text = build_markdown(payload)
    for section in (
        "## 1. Evaluation objective",
        "## 2. System components evaluated",
        "## 3. Corpus composition",
        "## 4. Test methodology",
        "## 5. Expected vs actual risk mapping",
        "## 6. Overall metrics",
        "## 7. Confusion-matrix interpretation",
        "## 8. Category-wise results",
        "## 9. False-positive analysis",
        "## 10. False-negative analysis",
        "## 11. Explainability verification",
        "## 12. Determinism verification",
        "## 13. No-network verification",
        "## 14. Limitations",
        "## 15. Reproducibility instructions",
        "## 16. Honest conclusion",
    ):
        assert section in text, section
    for term in ("detection rate", "precision", "recall", "false-positive rate"):
        assert term in text
    assert "80% accuracy" not in text


def test_repeated_payloads_match_apart_from_timestamp():
    _, first = _payload()
    _, second = _payload()
    first.pop("timestamp")
    second.pop("timestamp")
    assert first == second


def test_no_secrets_in_artifacts(tmp_path):
    results = run_all(load_cases()[:4])
    metrics = evaluate(results)
    paths = generate_reports(results, metrics, "0.1.0", tmp_path)
    combined = (
        Path(paths["results_json"]).read_text(encoding="utf-8")
        + Path(paths["report_md"]).read_text(encoding="utf-8")
    )
    for forbidden in ("SCAMSHIELD", "Auth-Key", "BEGIN PRIVATE",
                      os.path.expanduser("~"), os.environ.get("USERNAME", "definitely-not-set-xyz")):
        assert forbidden not in combined, forbidden


def test_evaluator_command_returns_zero():
    # main() always writes beside the real project root by design; the
    # content is deterministic, so regenerating it here is harmless.
    assert eval_main() == 0
    root = Path(__file__).resolve().parent.parent
    assert (root / "evaluation" / "results.json").exists()
    assert (root / "evaluation" / "report.md").exists()
