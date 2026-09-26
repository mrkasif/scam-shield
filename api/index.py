"""ScamShield FastAPI backend (Vercel-compatible).

Vercel treats ``api/index.py`` as a serverless function and imports the
module-level ``app``. Locally, run with::

    uvicorn api.index:app --reload --port 8000

The frontend in ``public/`` calls ``POST /api/analyze`` (relative URL),
so local + Vercel routing both work. Static analysis only — the backend
never fetches the submitted URL.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("scamshield")

# ---- input limits (reject, never silently truncate) ----
MAX_JSON_BODY_BYTES = 1 * 1024 * 1024  # 1 MB: text payloads are at most 4 KB
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB: mirrors the QR decoder cap
MAX_MULTIPART_BYTES = MAX_UPLOAD_BYTES + 1 * 1024 * 1024  # file + form overhead

# POST endpoints that only accept a JSON body.
_JSON_PATHS = frozenset(
    {"/api/analyze", "/analyze", "/api/analyze/upi"}
)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "no-referrer",
    # No inline scripts and no remote resources except Google Fonts
    # (which the frontend loads for display/body type) exist in public/,
    # so a strict same-origin CSP plus font allowances is safe. blob: is
    # required for the client-side QR image preview (URL.createObjectURL);
    # data: covers only the empty no-op favicon (all dynamic content uses
    # textContent, so no injected data: image can ever render).
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'self'"
    ),
}


class GuardMiddleware(BaseHTTPMiddleware):
    """Reject oversized bodies / wrong content types; stamp security headers."""

    async def dispatch(self, request: Request, call_next):
        if request.method == "POST":
            try:
                length = int(request.headers.get("content-length", "0") or "0")
            except ValueError:
                length = 0
            content_type = request.headers.get("content-type", "")
            if "multipart/" in content_type:
                if length > MAX_MULTIPART_BYTES:
                    return JSONResponse(
                        {"detail": "Upload is too large (max 10 MB)."},
                        status_code=413,
                    )
            else:
                if length > MAX_JSON_BODY_BYTES:
                    return JSONResponse(
                        {"detail": "Request body is too large."}, status_code=413
                    )
                if request.url.path in _JSON_PATHS and content_type:
                    if "application/json" not in content_type:
                        return JSONResponse(
                            {"detail": "Content-Type must be application/json."},
                            status_code=415,
                        )
        response = await call_next(request)
        for key, value in _SECURITY_HEADERS.items():
            response.headers[key] = value
        return response


async def read_limited(upload: UploadFile, limit: int) -> bytes:
    """Read an upload in chunks so huge files cannot exhaust memory."""
    chunks: list[bytes] = []
    received = 0
    while True:
        chunk = await upload.read(64 * 1024)
        if not chunk:
            break
        received += len(chunk)
        if received > limit:
            raise HTTPException(
                status_code=413, detail="Upload is too large (max 10 MB)."
            )
        chunks.append(chunk)
    return b"".join(chunks)

# Ensure ``src/`` (local checkout layout) is importable both locally and on Vercel.
ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scamshield.analyzer import (  # noqa: E402
    analyze_url,
    smart_scan_qr,
    smart_scan_text,
)
from scamshield.history import HistoryStore  # noqa: E402
from scamshield.qr.analyzer import analyze_qr_image  # noqa: E402
from scamshield.upi.analyzer import analyze_upi  # noqa: E402

app = FastAPI(title="ScamShield", version="0.1.0")

# CORS: the frontend is served same-origin (locally and on Vercel), so
# cross-origin access is denied by default. Set SCAMSHIELD_CORS_ORIGINS to a
# comma-separated allow-list only if the API must be called from elsewhere.
_cors_origins = [
    origin.strip()
    for origin in os.environ.get("SCAMSHIELD_CORS_ORIGINS", "").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=600,
)
app.add_middleware(GuardMiddleware)

# Scan history (metadata only). A history failure must never fail a scan,
# so every write below is best-effort with exceptions swallowed + logged.
history_store = HistoryStore(ROOT / "data" / "scamshield_history.db")


def _remember(envelope: dict) -> None:
    try:
        history_store.record(envelope)
    except Exception as exc:  # noqa: BLE001 - history must not break scans
        logger.warning("History write failed: %s", type(exc).__name__)


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    """Never leak tracebacks, paths, or internals to API callers."""
    if isinstance(exc, HTTPException):
        # Preserve the existing clean JSON error contract (Starlette would
        # otherwise route these through this generic handler via MRO).
        return JSONResponse(
            {"detail": exc.detail},
            status_code=exc.status_code,
            headers=exc.headers,
        )
    logger.exception("Unhandled %s on %s", type(exc).__name__, request.url.path)
    return JSONResponse({"detail": "Internal server error."}, status_code=500)


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


@app.get("/api/health")
@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "scamshield"}


@app.get("/api/status")
async def status() -> dict:
    """Live demo status: real subsystem state, read-only, no secrets."""
    try:
        import cv2  # noqa: F401

        qr_engine = "ready"
    except ImportError:
        qr_engine = "unavailable"
    from scamshield.evaluation.cases import CASES
    from scamshield.intel.database import get_default_database

    return {
        "scanner": "ready",
        "qr_engine": qr_engine,
        "local_intelligence": "ready",
        "local_indicators": get_default_database().size,
        "external_intelligence": (
            "configured"
            if os.environ.get("SCAMSHIELD_URLHAUS_AUTH_KEY", "").strip()
            else "not_configured"
        ),
        "evaluation_cases": len(CASES),
    }


@app.post("/api/analyze")
@app.post("/analyze")  # alias: Vercel rewrites may strip the /api prefix
async def analyze(payload: AnalyzeRequest) -> dict:
    raw = (payload.url or "").strip()
    if not raw:
        raise HTTPException(status_code=422, detail="URL must not be empty.")
    if len(raw) > 4096:
        raise HTTPException(status_code=422, detail="URL is too long.")
    try:
        return analyze_url(raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


class UpiRequest(BaseModel):
    upi_uri: str = Field(..., min_length=1, max_length=4096)


@app.post("/api/analyze/upi")
async def analyze_upi_uri(payload: UpiRequest) -> dict:
    """Statically analyze a UPI payment URI (never initiates/verifies)."""
    raw = payload.upi_uri or ""
    if not raw.strip():
        raise HTTPException(status_code=422, detail="UPI URI must not be empty.")
    if len(raw) > 4096:
        raise HTTPException(status_code=422, detail="UPI URI is too long.")
    try:
        return analyze_upi(raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/scan")
async def smart_scan(request: Request) -> dict:
    """Unified Smart Scanner: auto-detect input and route it (static only).

    Accepts JSON ``{"input": "<url|upi|text>"}`` or a multipart QR image
    upload (field ``file``). Returns the
    ``{"input_type": ..., "success": True, "result": ...}`` envelope.
    Individual endpoints are untouched; this only routes to them.
    """
    content_type = request.headers.get("content-type", "")
    if "multipart/" in content_type:
        form = await request.form()
        upload = form.get("file") or form.get("qr") or form.get("image")
        if upload is None or not hasattr(upload, "read"):
            raise HTTPException(status_code=422, detail="No QR image supplied.")
        if getattr(upload, "content_type", None) and not upload.content_type.startswith("image/"):
            logger.warning("Rejected non-image upload: %s", upload.content_type)
            raise HTTPException(
                status_code=422, detail="An image file is required (PNG or JPEG)."
            )
        raw = await read_limited(upload, MAX_UPLOAD_BYTES)
        if not raw:
            raise HTTPException(status_code=422, detail="Uploaded image is empty.")
        try:
            envelope = smart_scan_qr(raw)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except RuntimeError as exc:  # QR engine not installed on this host
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        _remember(envelope)
        return envelope
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(
            status_code=422, detail="Request body must be JSON {\"input\": \"...\"}."
        ) from exc
    if not isinstance(body, dict) or not isinstance(body.get("input"), str):
        raise HTTPException(
            status_code=422, detail="Request body must be JSON {\"input\": \"...\"}."
        )
    raw_text: str = body["input"]
    if not raw_text.strip():
        raise HTTPException(status_code=422, detail="Input must not be empty.")
    if len(raw_text) > 4096:
        raise HTTPException(status_code=422, detail="Input is too long.")
    try:
        envelope = smart_scan_text(raw_text)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    _remember(envelope)
    return envelope


@app.get("/api/history")
async def get_history(limit: int = 50) -> dict:
    """Recent scans, newest first (sanitized metadata only)."""
    return {"scans": history_store.list(limit), "persistent": history_store.persistent}


@app.get("/api/history/stats")
async def get_history_stats() -> dict:
    """Aggregate statistics over stored scans."""
    return history_store.stats()


@app.delete("/api/history")
async def clear_history() -> dict:
    """Delete all stored scan history."""
    return {"cleared": history_store.clear()}


@app.post("/api/analyze/qr")
async def analyze_qr(file: UploadFile = File(...)) -> dict:
    """Decode an uploaded QR image and analyze its payload (static only).

    URL payloads are passed to the existing URL analyzer. The decoded
    destination is never visited, fetched, or opened.
    """
    if not file.content_type or not file.content_type.startswith("image/"):
        logger.warning("Rejected non-image upload: %s", file.content_type)
        raise HTTPException(
            status_code=422, detail="An image file is required (PNG or JPEG)."
        )
    raw = await read_limited(file, MAX_UPLOAD_BYTES)
    if not raw:
        raise HTTPException(status_code=422, detail="Uploaded image is empty.")
    try:
        return analyze_qr_image(raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:  # QR engine not installed on this host
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# Local convenience: serve the static frontend from the same process.
# On Vercel the ``public/`` directory is served separately via vercel.json,
# so this mount is skipped there if the directory layout differs.
PUBLIC_DIR = ROOT / "public"
if PUBLIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(PUBLIC_DIR), html=True), name="static")
