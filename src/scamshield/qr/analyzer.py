"""QR image decoding + payload classification (static analysis only).

Pipeline: QR image bytes -> OpenCV decode -> payload string -> payload type.
URL payloads are passed to the EXISTING URL analyzer
(:func:`scamshield.analyzer.analyze_url`) and UPI payloads to the
EXISTING UPI analyzer (:func:`scamshield.upi.analyzer.analyze_upi`);
no URL/UPI logic is duplicated here.

Security: this module never fetches, opens, or executes anything. The
decoded payload is treated as untrusted text throughout.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

try:  # OpenCV is optional: slim hosts (e.g. Vercel free tier) skip it.
    import cv2
    import numpy as np

    _CV2_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via no-cv2 simulation
    cv2 = None  # type: ignore[assignment]
    np = None  # type: ignore[assignment]
    _CV2_AVAILABLE = False

from ..analyzer import analyze_url
from ..upi.analyzer import analyze_upi
from ..url.analyzer import is_url_text

MAX_IMAGE_BYTES = 10 * 1024 * 1024  # 10 MB upload cap
MAX_IMAGE_SIDE = 10_000  # pixels per side
MAX_IMAGE_PIXELS = 25_000_000  # ~25 MP: stops decompression bombs, allows photos

NOT_OPENED_NOTE = (
    "The destination was NOT opened or visited. "
    "This verdict comes from static analysis of the link structure only."
)

QR_ENGINE_UNAVAILABLE = (
    "QR image decoding is unavailable on this host "
    "(OpenCV is not installed). URL, UPI, and text scans are unaffected."
)


def qr_engine_available() -> bool:
    """True when image decoding is possible on this host."""
    return _CV2_AVAILABLE

_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]{1,19}:")

# Labels shown for UPI query parameters (parsed statically, never acted on).
_UPI_LABELS = {
    "pa": "payee address",
    "pn": "payee name",
    "am": "amount",
    "cu": "currency",
    "tn": "note",
    "tr": "transaction ref",
}

_UPI_STATIC_NOTE = (
    "ScamShield performs static analysis only. "
    "It does not initiate or verify payments."
)


def _decode_with_detector(img) -> str | None:
    """Return payload, "" if a (empty) QR was located, None if none found."""
    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(img)
    if data:
        return data
    try:
        ok, decoded_list, _, _ = detector.detectAndDecodeMulti(img)
    except Exception:  # pragma: no cover - build-dependent API
        ok, decoded_list = False, []
    if ok and decoded_list is not None:
        for item in list(decoded_list):
            if item:
                return item
    if bbox is not None:
        return ""  # QR symbol located but carries no payload
    return None


def decode_qr_image(image_bytes: bytes) -> str | None:
    """Decode a QR code from raw image bytes using OpenCV.

    Returns the payload string, ``""`` if a QR symbol was found but is
    empty, or ``None`` when no QR code is detected. Raises ``ValueError``
    when the bytes are not a decodable image, ``RuntimeError`` when the
    QR engine is not installed on this host.
    """
    if not _CV2_AVAILABLE:
        raise RuntimeError(QR_ENGINE_UNAVAILABLE)
    if not image_bytes:
        raise ValueError("No image data supplied.")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise ValueError("Image is too large (max 10 MB).")
    buf = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(buf, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Uploaded file is not a valid image.")
    height, width = img.shape[:2]
    if (
        height > MAX_IMAGE_SIDE
        or width > MAX_IMAGE_SIDE
        or height * width > MAX_IMAGE_PIXELS
    ):
        raise ValueError("Image dimensions are too large.")
    result = _decode_with_detector(img)
    if result is None:
        # Retry once enlarged: tiny uploads often fail at native resolution.
        height, width = img.shape[:2]
        if max(height, width) < 400:
            scale = 800 / max(height, width)
            enlarged = cv2.resize(
                img, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC
            )
            result = _decode_with_detector(enlarged)
    return result


def _as_url(payload: str) -> str | None:
    """Return the payload if it is an http(s) URL, else None.

    Thin alias over the shared :func:`url.analyzer.is_url_text` check so
    QR-side URL detection can never drift from the rest of the system.
    """
    return is_url_text(payload)


def _parse_upi_details(payload: str) -> dict:
    """Statically parse informational UPI parameters (no validation/payment)."""
    text = payload.strip()
    query = urlsplit(text).query if "?" in text else ""
    details: dict = {}
    try:
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError:
        pairs = []
    for key, value in pairs:
        label = _UPI_LABELS.get(key.lower(), key)
        if value:
            details[label] = value
    return details


def classify_payload(payload: str) -> dict:
    """Classify a decoded QR payload without opening or executing it."""
    text = (payload or "")
    stripped = text.strip()

    if not stripped:
        return {
            "type": "empty",
            "payload": "",
            "classification": "empty_payload",
            "note": "The QR code decoded successfully but carries no content.",
        }

    if stripped.lower().startswith("upi://"):
        try:
            upi_analysis = analyze_upi(text)
        except ValueError as exc:
            return {
                "type": "upi",
                "payload": text,
                "classification": "malformed_request",
                "note": (
                    "This QR looks like a UPI payment request, but it could "
                    f"not be parsed ({exc}). Do not act on it. "
                    + _UPI_STATIC_NOTE
                ),
            }
        # Reuse the existing Step 4 analyzer — the single source of truth
        # for UPI verdicts. The URI is analyzed statically only: nothing is
        # initiated, contacted, or verified.
        return {
            "type": "upi",
            "payload": text,
            "classification": "payment_request",
            "upi_details": _parse_upi_details(text),
            "analysis": upi_analysis,
            "note": _UPI_STATIC_NOTE,
        }

    url = _as_url(text)
    if url is not None:
        # Reuse the existing Step 1 analyzer — the single source of truth
        # for URL verdicts. The decoded URL is analyzed statically only.
        return {
            "type": "url",
            "payload": text,
            "analysis": analyze_url(url),
            "note": NOT_OPENED_NOTE,
        }

    if _SCHEME_RE.match(stripped):
        return {
            "type": "unknown",
            "payload": text,
            "classification": "non_web_uri",
            "note": (
                "This QR encodes a non-web URI (not an http(s) link), so no "
                "link risk score applies. Do not act on it unless you trust "
                "the source."
            ),
        }

    return {
        "type": "text",
        "payload": text,
        "classification": "plain_text",
        "note": (
            "This QR contains plain text, not a link — so no risk score "
            "applies and it is NOT marked safe. Read it critically; text "
            "can still carry scam instructions."
        ),
    }


def analyze_qr_image(image_bytes: bytes) -> dict:
    """Full pipeline: decode image bytes -> classify payload -> analyze.

    Raises ``ValueError`` when the image is invalid or contains no QR code.
    """
    payload = decode_qr_image(image_bytes)
    if payload is None:
        raise ValueError("No QR code could be decoded from the image.")
    return classify_payload(payload)
