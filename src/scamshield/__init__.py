"""ScamShield core package."""

from .analyzer import analyze_url, detect_input_type, smart_scan_qr, smart_scan_text

__all__ = ["analyze_url", "detect_input_type", "smart_scan_qr", "smart_scan_text"]
__version__ = "0.1.0"
