from __future__ import annotations

import logging
import time
from pathlib import Path

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATES_DIR = ROOT / "templates"
STATIC_DIR = ROOT / "static"

app = FastAPI(docs_url=None, redoc_url=None)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# --- Security + cache middleware ---

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'"
    ),
}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    else:
        response.headers["Cache-Control"] = "no-cache"
    return response


# --- Rate limiting for contact form ---

_contact_timestamps: dict[str, list[float]] = {}
CONTACT_RATE_LIMIT = 5  # per hour
CONTACT_WINDOW = 3600  # seconds


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    timestamps = _contact_timestamps.get(ip, [])
    timestamps = [t for t in timestamps if now - t < CONTACT_WINDOW]
    _contact_timestamps[ip] = timestamps
    return len(timestamps) >= CONTACT_RATE_LIMIT


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
    name: str = Form(...),
    email: str = Form(...),
    message: str = Form(...),
    website: str = Form(""),  # honeypot field
):
    # Honeypot — bots fill hidden fields
    if website:
        return JSONResponse({"status": "ok"})  # silent drop

    client_ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_ip):
        return JSONResponse({"status": "ok"})  # silent drop, don't reveal rate limit

    _contact_timestamps.setdefault(client_ip, []).append(time.time())

    # Log submission (replace with email delivery later)
    logger.info("Contact form submission from %s <%s>", name, email)

    return JSONResponse({"status": "ok", "message": "Message received. I'll get back to you."})


@app.exception_handler(404)
async def not_found(request: Request, _exc):
    return templates.TemplateResponse(request, "index.html", status_code=404)
