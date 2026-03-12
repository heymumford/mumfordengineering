from __future__ import annotations

import logging
import re
import time
from pathlib import Path

from fastapi import FastAPI, Request, Form, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATES_DIR = ROOT / "templates"
STATIC_DIR = ROOT / "static"

app = FastAPI(docs_url=None, redoc_url=None)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# --- Security + cache middleware ---

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), payment=(), "
        "display-capture=(), accelerometer=(), gyroscope=(), usb=(), "
        "magnetometer=(), picture-in-picture=()"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "script-src 'self'; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'"
    ),
}

# Allowlist-style email regex: alphanumeric + common specials only
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
_MAX_NAME = 200
_MAX_EMAIL = 254
_MAX_MESSAGE = 5000
_MAX_BODY_BYTES = 1_048_576  # 1 MB


@app.middleware("http")
async def reject_null_bytes(request: Request, call_next):
    """Block requests with null bytes in the path (prevents StaticFiles ValueError)."""
    if "\x00" in request.url.path:
        return JSONResponse({"error": "bad request"}, status_code=400)
    return await call_next(request)


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    """Reject requests with declared body larger than 1 MB.

    Checks Content-Length header for early rejection. Chunked transfers
    without Content-Length are bounded by Fly.io's proxy (1 MB default)
    and by FastAPI's Form() max_length on individual fields.
    """
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > _MAX_BODY_BYTES:
                return JSONResponse({"error": "payload too large"}, status_code=413)
        except ValueError:
            pass
    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Unhandled error in request handler")
        response = JSONResponse({"error": "internal server error"}, status_code=500)
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    if request.url.path.startswith("/static/") and response.status_code == 200:
        response.headers["Cache-Control"] = "public, max-age=86400, must-revalidate"
    else:
        response.headers["Cache-Control"] = "no-cache"
    return response


# --- Custom validation error handler (prevent input reflection) ---


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        {"status": "error", "message": "Invalid form data."},
        status_code=422,
    )


# --- Rate limiting for contact form ---

_contact_timestamps: dict[str, list[float]] = {}
_MAX_TRACKED_IPS = 10_000
CONTACT_RATE_LIMIT = 5  # per hour
CONTACT_WINDOW = 3600  # seconds


def _get_client_ip(request: Request) -> str:
    """Extract real client IP from Fly.io proxy headers.

    Only trusts fly-client-ip (set by Fly.io proxy, not spoofable from
    outside the proxy). Does not rely on request.client, which may be
    derived from proxy headers such as X-Forwarded-For.
    """
    ip = request.headers.get("fly-client-ip")
    if ip:
        return ip.strip()
    # When fly-client-ip is absent, avoid trusting request.client because
    # some ASGI servers/middleware may populate it from spoofable headers.
    return "unknown"


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    timestamps = [t for t in _contact_timestamps.get(ip, []) if now - t < CONTACT_WINDOW]
    if len(timestamps) >= CONTACT_RATE_LIMIT:
        _contact_timestamps[ip] = timestamps
        return True
    timestamps.append(now)
    _contact_timestamps[ip] = timestamps
    return False


# Unicode categories that should not appear in log output
_LOG_UNSAFE_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")


def _sanitize_log(value: str) -> str:
    """Strip control characters, bidi overrides, and zero-width chars for safe logging."""
    return _LOG_UNSAFE_RE.sub("", value)[:200]


def _clean_field(value: str) -> str:
    """Strip BOM, null bytes, and whitespace from a form field."""
    return value.replace("\x00", "").lstrip("\ufeff").strip()


# --- Routes ---


@app.head("/health")
async def health_head():
    return Response(status_code=200, media_type="application/json")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.head("/", response_class=HTMLResponse)
async def index_head():
    return Response(status_code=200, media_type="text/html")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.post("/contact")
async def contact(
    request: Request,
    name: str = Form(..., max_length=_MAX_NAME),
    email: str = Form(..., max_length=_MAX_EMAIL),
    message: str = Form(..., max_length=_MAX_MESSAGE),
    website: str = Form(""),  # honeypot field
):
    # Honeypot -- bots fill hidden fields
    if website:
        return JSONResponse({"status": "ok", "message": "Message received. I'll get back to you."})

    name = _clean_field(name)
    email = _clean_field(email)
    message = _clean_field(message)

    if not name or not email or not message:
        return JSONResponse({"status": "error", "message": "All fields are required."}, status_code=422)

    if not _EMAIL_RE.match(email):
        return JSONResponse({"status": "error", "message": "Please enter a valid email address."}, status_code=422)

    client_ip = _get_client_ip(request)
    if _is_rate_limited(client_ip):
        return JSONResponse({"status": "ok", "message": "Message received. I'll get back to you."})

    # Evict oldest IPs if tracking too many
    if len(_contact_timestamps) > _MAX_TRACKED_IPS:
        oldest_ip = min(_contact_timestamps, key=lambda k: _contact_timestamps[k][-1])
        del _contact_timestamps[oldest_ip]

    logger.info("Contact form submission received from %s", _sanitize_log(email))

    return JSONResponse({"status": "ok", "message": "Message received. I'll get back to you."})


@app.exception_handler(404)
async def not_found(request: Request, _exc):
    return templates.TemplateResponse(request, "index.html", status_code=404)
