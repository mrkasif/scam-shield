"""In-memory intelligence database (loaded once from the local dataset)."""

from __future__ import annotations

from .dataset import RECORDS
from .models import IntelRecord


class IntelDatabase:
    """Exact-lookup indexes over curated records. No I/O after init."""

    def __init__(self, records: tuple[IntelRecord, ...] = RECORDS) -> None:
        self._domains: dict[str, IntelRecord] = {}
        self._hostnames: dict[str, IntelRecord] = {}
        self._upi_handles: dict[str, IntelRecord] = {}
        for record in records:
            key = record.indicator.strip().lower()
            if record.indicator_type == "domain":
                self._domains[key] = record
            elif record.indicator_type == "hostname":
                self._hostnames[key] = record
            elif record.indicator_type == "upi_handle":
                self._upi_handles[key] = record

    @property
    def size(self) -> int:
        return len(self._domains) + len(self._hostnames) + len(self._upi_handles)

    def lookup_domain(self, registrable_domain: str) -> IntelRecord | None:
        return self._domains.get((registrable_domain or "").strip().lower())

    def lookup_hostname(self, hostname: str) -> IntelRecord | None:
        return self._hostnames.get((hostname or "").strip().lower())

    def lookup_upi_handle(self, payee_id: str) -> IntelRecord | None:
        return self._upi_handles.get((payee_id or "").strip().lower())


_default_db: IntelDatabase | None = None


def get_default_database() -> IntelDatabase:
    """Process-wide singleton (dataset is static, so one copy suffices)."""
    global _default_db
    if _default_db is None:
        _default_db = IntelDatabase()
    return _default_db
