"""Deterministic evaluation metrics (pure functions, no I/O).

Positive class: a case is a *threat* when its expected class is SUSPICIOUS
or HIGH_RISK, and is *predicted* threat when the analyzer returns YELLOW or
RED. SAFE expectations form the negative class. DECODE_ERROR cases are
counted in totals only.
"""

from __future__ import annotations

_THREAT = frozenset({"SUSPICIOUS", "HIGH_RISK"})


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def evaluate(results: list[dict]) -> dict:
    """Compute summary, confusion, risk distribution, categories, explanations."""
    classified = [r for r in results if r["expected_class"] in _THREAT or r["expected_class"] == "SAFE"]

    tp = sum(1 for r in classified if r["expected_class"] in _THREAT and (r["actual_class"] or "") in _THREAT)
    fn = sum(1 for r in classified if r["expected_class"] in _THREAT and (r["actual_class"] or "") not in _THREAT)
    tn = sum(1 for r in classified if r["expected_class"] == "SAFE" and r["actual_class"] == "SAFE")
    fp = sum(1 for r in classified if r["expected_class"] == "SAFE" and r["actual_class"] != "SAFE")

    threat_total = tp + fn
    safe_total = tn + fp
    precision = _rate(tp, tp + fp)
    recall = _rate(tp, threat_total)

    risk_counts = {"GREEN": 0, "YELLOW": 0, "RED": 0, "unscored": 0}
    for r in results:
        level = r.get("risk_level")
        if level in risk_counts:
            risk_counts[level] += 1
        else:
            risk_counts["unscored"] += 1

    categories: dict[str, dict] = {}
    for r in results:
        bucket = categories.setdefault(
            r["expected_category"], {"cases": 0, "passed": 0, "failed": 0}
        )
        bucket["cases"] += 1
        if r["passed"]:
            bucket["passed"] += 1
        else:
            bucket["failed"] += 1

    explained = [r for r in results if r.get("explainability") is True]
    unexplained = [r for r in results if r.get("explainability") is False]

    return {
        "total": len(results),
        "passed": sum(1 for r in results if r["passed"]),
        "failed": sum(1 for r in results if not r["passed"]),
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "detection_rate": recall,
        "false_positive_rate": _rate(fp, safe_total),
        "precision": precision,
        "recall": recall,
        "risk_distribution": risk_counts,
        "categories": categories,
        "explained": len(explained),
        "unexplained": len(unexplained),
    }
