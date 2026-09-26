"""URL subpackage for ScamShield static analysis."""

from .analyzer import analyze_url_parts, is_url_text, normalize_url

__all__ = ["analyze_url_parts", "is_url_text", "normalize_url"]
