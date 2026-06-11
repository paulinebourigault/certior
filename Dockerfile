FROM python:3.12-slim AS base

WORKDIR /app

# System deps (build-essential needed for z3-solver wheel)
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*

# ── Dependency layer (cached unless pyproject.toml changes) ───────────
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir --upgrade pip wheel setuptools && \
    pip install --no-cache-dir ".[all]"

# ── Application layer ────────────────────────────────────────────────
COPY agentsafe/ agentsafe/
COPY app/       app/
COPY skills/    skills/

# Re-install in editable mode so console scripts and package metadata work
RUN pip install --no-cache-dir --no-deps -e .

# ── Runtime configuration ─────────────────────────────────────────────
RUN mkdir -p /data /workspace

ENV CERTIOR_WORKSPACE=/workspace \
    CERTIOR_ENV=production \
    CERTIOR_HOST=0.0.0.0 \
    CERTIOR_PORT=8000 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
