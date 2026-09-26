"""External intelligence providers (URLhaus first, interface-led)."""

from .urlhaus import UrlhausProvider

__all__ = ["UrlhausProvider"]
