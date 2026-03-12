from __future__ import annotations

import logging
import re
import time
from pathlib import Path

from fastapi import FastAPI, Request, Form
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
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "script-src 'self'; "
        "connect-src 'self'"
    ),
}

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MAX_NAME = 200
_MAX_EMAIL = 254
_MAX_MESSAGE = 5000


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Unhandled error in request handler")
        response = JSONResponse({"error": "internal server error"}, status_code=500)
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=86400, must-revalidate"
    else:
        response.headers["Cache-Control"] = "no-cache"
    return response


# --- Rate limiting for contact form ---

_contact_timestamps: dict[str, list[float]] = {}
_MAX_TRACKED_IPS = 10_000
CONTACT_RATE_LIMIT = 5  # per hour
CONTACT_WINDOW = 3600  # seconds


def _get_client_ip(request: Request) -> str:
    """Extract real client IP from Fly.io proxy headers."""
    ip = request.headers.get("fly-client-ip")
    if ip:
        return ip.strip()
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    timestamps = _contact_timestamps.get(ip, [])
    timestamps = [t for t in timestamps if now - t < CONTACT_WINDOW]
    if not timestamps:
        _contact_timestamps.pop(ip, None)
        return False
    _contact_timestamps[ip] = timestamps
    if len(timestamps) >= CONTACT_RATE_LIMIT:
        return True
    timestamps.append(now)
    return False


def _sanitize_log(value: str) -> str:
    """Strip control characters for safe logging."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "", value)[:200]


# --- Routes ---


@app.get("/health")
async def health():
    return {"status": "ok"}


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
    # Honeypot — bots fill hidden fields
    if website:
        return JSONResponse({"status": "ok", "message": "Message received. I'll get back to you."})

    name = name.strip()
    email = email.strip()
    message = message.strip()

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
