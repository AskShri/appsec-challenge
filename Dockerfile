# =============================================================================
# Multi-stage Dockerfile — Secure Login Portal (Production)
#
# Security hardening:
# - Multi-stage build (build deps don't ship in runtime image)
# - Non-root user (appuser, UID 1000)
# - Minimal base image (python:3.9-slim-bookworm)
# - No development tools, compilers, or debug utilities in runtime
# - Read-only filesystem (enforced via docker-compose)
# - Health check built-in
# - Pinned base image for reproducibility
#
# Build:  docker build -t secure-login-portal .
# Run:    docker-compose up
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder — install Python dependencies
# ---------------------------------------------------------------------------
FROM python:3.9-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies for bcrypt's C extension.
# These are only needed at build time, not in the runtime image.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first (Docker layer caching).
# Changes to application code won't re-trigger dependency install.
COPY requirements.txt .

# Install Python packages into a virtual environment.
# Using venv makes it easy to copy only the installed packages to runtime.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn>=22.0,<23.0

# ---------------------------------------------------------------------------
# Stage 2: Runtime — minimal image with only what's needed to run
# ---------------------------------------------------------------------------
FROM python:3.9-slim-bookworm AS runtime

# Metadata labels (OCI standard).
LABEL org.opencontainers.image.title="Secure Login Portal" \
      org.opencontainers.image.description="Flask-based secure authentication portal with defense-in-depth" \
      org.opencontainers.image.authors="Security Engineering Lead" \
      org.opencontainers.image.source="https://github.com/xero-appsec-challenge"

# --- Security: Non-root user ---
# Create a dedicated user with no shell and no home directory.
# UID 1000 avoids conflicts with system users.
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /usr/sbin/nologin --no-create-home appuser

# --- Security: Remove unnecessary packages ---
# Slim image is already minimal, but remove anything we definitely don't need.
RUN apt-get update && \
    apt-get remove -y --allow-remove-essential \
        e2fsprogs \
    ; apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy the virtual environment from the builder stage.
# This contains only runtime packages — no gcc, no build headers.
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# --- Application Code ---
WORKDIR /app

# Copy application code (see .dockerignore for excluded files).
COPY app/ ./app/
COPY run.py wsgi.py gunicorn.conf.py ./

# --- Writable Directories ---
# Create directories that the app needs to write to.
# In docker-compose, the root filesystem is read-only;
# these directories are mounted as tmpfs.
RUN mkdir -p /app/instance /app/instance/flask_sessions && \
    chown -R appuser:appuser /app/instance

# --- Environment ---
# PYTHONDONTWRITEBYTECODE: Don't create .pyc files (read-only filesystem).
# PYTHONUNBUFFERED: Ensure logs are flushed immediately to stdout/stderr.
# FLASK_APP: Tell Flask where the application factory is.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=run.py

# --- Health Check ---
# Verify the application is responding.
# Uses Python instead of curl to avoid installing curl in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/login')" || exit 1

# --- Switch to non-root user ---
USER appuser

# --- Expose port ---
# gunicorn listens on 8000 by default (configured in gunicorn.conf.py).
# This is documentation only — actual port mapping is in docker-compose.
EXPOSE 8000

# --- Entrypoint ---
# Run gunicorn with the production config.
# wsgi.py validates SECRET_KEY, creates the app with ProductionConfig.
CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
