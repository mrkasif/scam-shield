"""Evaluation lab package: offline measurement of the current analyzers."""

EVALUATOR_VERSION = "1.0.0"

from .cases import CASES, EvaluationCase, load_cases
from .metrics import evaluate
from .report import generate_reports
from .runner import run_all, run_case

__all__ = [
    "CASES",
    "EVALUATOR_VERSION",
    "EvaluationCase",
    "evaluate",
    "generate_reports",
    "load_cases",
    "run_all",
    "run_case",
]
