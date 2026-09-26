"""Local threat-intelligence layer (offline evidence source, Step 8)."""

from .database import IntelDatabase, get_default_database
from .matcher import match_upi, match_url
from .models import IntelRecord

__all__ = ["IntelDatabase", "IntelRecord", "get_default_database", "match_upi", "match_url"]
