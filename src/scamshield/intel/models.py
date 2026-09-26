"""Intelligence record model (pure data, no I/O, no network)."""

from __future__ import annotations

from dataclasses import dataclass

VALID_TYPES = frozenset({"domain", "hostname", "upi_handle"})
VALID_SEVERITIES = frozenset({"low", "medium", "high"})


@dataclass(frozen=True)
class IntelRecord:
    indicator: str
    indicator_type: str
    category: str
    severity: str
    description: str
    source: str
    confidence: float

    def __post_init__(self) -> None:
        if self.indicator_type not in VALID_TYPES:
            raise ValueError(f"Bad indicator_type: {self.indicator_type!r}.")
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Bad severity: {self.severity!r}.")
        if not self.indicator or not self.indicator.strip():
            raise ValueError("Indicator must not be empty.")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0.")

    def to_dict(self) -> dict:
        return {
            "indicator_type": self.indicator_type,
            "indicator": self.indicator,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "description": self.description,
        }
