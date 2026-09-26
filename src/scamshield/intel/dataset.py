"""Curated demo intelligence dataset (offline, clearly labeled).

Every record below uses a reserved ``.example`` identifier that can never
belong to a real victim or attacker, and is labeled
``ScamShield Demo Intelligence``. No real-world domain or UPI handle is
claimed to be malicious anywhere in this project.
"""

from __future__ import annotations

from .models import IntelRecord

SOURCE = "ScamShield Demo Intelligence"

RECORDS: tuple[IntelRecord, ...] = (
    IntelRecord(
        indicator="malicious.example",
        indicator_type="domain",
        category="malware",
        severity="high",
        confidence=0.95,
        source=SOURCE,
        description="Demo intelligence indicator for testing.",
    ),
    IntelRecord(
        indicator="phishing.example",
        indicator_type="domain",
        category="phishing",
        severity="high",
        confidence=0.95,
        source=SOURCE,
        description="Demo intelligence indicator for testing.",
    ),
    IntelRecord(
        indicator="scam.example",
        indicator_type="domain",
        category="scam",
        severity="medium",
        confidence=0.9,
        source=SOURCE,
        description="Demo intelligence indicator for testing.",
    ),
    IntelRecord(
        indicator="secure.phishing.example",
        indicator_type="hostname",
        category="phishing",
        severity="high",
        confidence=0.92,
        source=SOURCE,
        description="Demo intelligence indicator for testing.",
    ),
    IntelRecord(
        indicator="scammer@demoupi",
        indicator_type="upi_handle",
        category="scam",
        severity="high",
        confidence=0.9,
        source=SOURCE,
        description="Demo intelligence indicator for testing.",
    ),
)
