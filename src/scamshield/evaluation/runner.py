"""Evaluation runner: feeds cases through the real analyzers (offline only).

Uses the public functions directly (``analyze_url`` / ``analyze_upi`` /
``analyze_qr_image``) — never the Smart Scanner facade, so no URLhaus or
other external lookup can be triggered. QR fixtures are generated in-memory.
"""

from __future__ import annotations

import io

from .cases import EvaluationCase

_RISK_TO_CLASS = {"GREEN": "SAFE", "YELLOW": "SUSPICIOUS", "RED": "HIGH_RISK"}
_THREAT_CLASSES = frozenset({"SUSPICIOUS", "HIGH_RISK"})


def _blank_png(size: int = 200) -> bytes:
    from PIL import Image

    img = Image.new("RGB", (size, size), color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _qr_png(data: str) -> bytes:
    import qrcode

    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _from_verdict(result: dict) -> tuple[str, str | None, int | None]:
    return (
        _RISK_TO_CLASS[result["risk_level"]],
        result.get("category"),
        result.get("score"),
    )


def run_case(case: EvaluationCase) -> dict:
    """Execute one case; never raises (unexpected errors become failures)."""
    from ..analyzer import analyze_url
    from ..qr.analyzer import analyze_qr_image
    from ..upi.analyzer import analyze_upi

    outcome: dict = {
        "id": case.id,
        "name": case.name,
        "input_type": case.input_type,
        "expected_class": case.expected_class,
        "expected_category": case.expected_category,
        "actual_class": None,
        "actual_category": None,
        "score": None,
        "risk_level": None,
        "reasons": [],
        "detected_indicators": [],
        "passed": False,
        "category_match": False,
        "explainability": None,
        "error": None,
    }
    try:
        if case.input_type == "url":
            out = analyze_url(case.input)
            actual_class, category, score = _from_verdict(out)
            outcome.update(
                actual_class=actual_class, actual_category=category,
                score=score, risk_level=out["risk_level"],
                reasons=out["reasons"], detected_indicators=out["detected_indicators"],
            )
        elif case.input_type == "upi":
            out = analyze_upi(case.input)
            actual_class, category, score = _from_verdict(out)
            outcome.update(
                actual_class=actual_class, actual_category=category,
                score=score, risk_level=out["risk_level"],
                reasons=out["reasons"], detected_indicators=out["detected_indicators"],
            )
        elif case.input_type in ("qr_url", "qr_upi", "qr_text"):
            decoded = analyze_qr_image(_qr_png(case.input))
            inner = decoded.get("type")
            analysis = decoded.get("analysis") or {}
            if inner in ("url", "upi") and isinstance(analysis.get("score"), int):
                actual_class = _RISK_TO_CLASS[analysis["risk_level"]]
                outcome.update(
                    actual_class=actual_class, actual_category=analysis.get("category"),
                    score=analysis.get("score"), risk_level=analysis.get("risk_level"),
                    reasons=analysis.get("reasons", []),
                    detected_indicators=analysis.get("detected_indicators", []),
                )
            elif inner == "text":
                # Correct handling: decoded as text, no score, no false alarm.
                outcome.update(actual_class="SAFE", actual_category="plain_text")
            else:
                outcome["error"] = f"Unexpected QR inner type: {inner!r}."
        elif case.input_type == "qr_bad":
            try:
                found = analyze_qr_image(_blank_png())
            except ValueError:
                found = None
            if found is None:
                outcome.update(actual_class="DECODE_ERROR", actual_category="decode_error")
            else:
                outcome["error"] = "Blank image unexpectedly decoded."
        else:
            outcome["error"] = f"Unknown input_type: {case.input_type!r}."
    except ValueError as exc:
        outcome["error"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001 - evaluator must not crash
        outcome["error"] = f"UNEXPECTED {type(exc).__name__}: {exc}"

    outcome["category_match"] = (
        outcome["actual_category"] == case.expected_category
    )
    outcome["passed"] = (
        outcome["error"] is None
        and outcome["actual_class"] == case.expected_class
        and outcome["category_match"]
    )
    # Explainability: threat predictions must carry reasons + indicators.
    if outcome["actual_class"] in _THREAT_CLASSES:
        benign_line = "No phishing indicators detected in static analysis."
        outcome["explainability"] = bool(
            outcome["reasons"]
            and outcome["reasons"] != [benign_line]
            and outcome["reasons"] != ["No suspicious payment characteristics detected in static analysis."]
            and outcome["detected_indicators"]
        )
    return outcome


def run_all(cases) -> list[dict]:
    """Run every case deterministically (input order preserved)."""
    return [run_case(case) for case in cases]
