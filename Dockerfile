FROM python:3.12-slim AS builder

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir "uv>=0.6.0,<0.7" && uv sync --frozen --no-dev

FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

COPY --from=builder /app/.venv /app/.venv
COPY src/ src/
COPY templates/ templates/
COPY static/ static/

RUN adduser --system --no-create-home appuser
USER appuser

ENV PYTHONPATH=/app/src
ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

CMD ["sh", "-c", "uvicorn mumfordengineering.app:app --host 0.0.0.0 --port 8080 --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-}\" --timeout-graceful-shutdown 10"]
