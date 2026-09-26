"""External intelligence provider interface (offline-safe by contract)."""

from __future__ import annotations

from typing import Protocol


class IntelProvider(Protocol):
    """Minimal interface every external provider must implement."""

    name: str

    def check_url(self, url: str) -> dict:
        """Look up a URL indicator, returning a normalized envelope.

        The envelope always has ``provider``, ``configured``, ``available``,
        ``matched``, ``findings`` and ``error`` keys. The method must never
        raise for provider-side problems and must never fetch the submitted
        destination itself — only the provider's threat-intel API.
        """
        ...
