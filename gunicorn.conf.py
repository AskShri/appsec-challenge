"""
Gunicorn configuration for production deployment.

Usage:
    gunicorn -c gunicorn.conf.py "app:create_app()"

Security considerations:
- Workers are pre-forked (not threaded) to isolate request handling
- Timeouts prevent slow-loris DoS attacks
- Access log format excludes sensitive data (no request bodies)
- Worker recycling (max_requests) mitigates memory leak risks
"""

import multiprocessing
import os

# --- Bind ---
# Listen on all interfaces inside the container.
# The container's port mapping controls external exposure.
bind = os.environ.get('GUNICORN_BIND', '0.0.0.0:8000')

# --- Workers ---
# Pre-fork worker model: each worker is an isolated process.
# Formula: 2 * CPU cores + 1 (gunicorn recommendation).
# Cap at 4 for a login portal — not a high-throughput API.
workers = min(multiprocessing.cpu_count() * 2 + 1, 4)
worker_class = 'sync'  # Sync workers are simplest and sufficient for login flows

# --- Timeouts ---
# Request timeout: 30s is generous for a login form.
# bcrypt takes ~250ms; the rest is network overhead.
timeout = 30
# Graceful shutdown: allow 10s for in-flight requests to complete.
graceful_timeout = 10
# Keep-alive: 2s default, matches nginx proxy_read_timeout expectations.
keepalive = 2

# --- Worker Recycling ---
# Restart workers after this many requests to prevent memory leaks.
# Jitter prevents all workers from restarting simultaneously.
max_requests = 1000
max_requests_jitter = 50

# --- Security ---
# Limit request sizes to match Flask's MAX_CONTENT_LENGTH (16KB).
# Stops oversized payloads at the WSGI layer before they reach Flask.
limit_request_line = 8190          # Max URL length (bytes)
limit_request_fields = 50          # Max number of headers
limit_request_field_size = 8190    # Max header value length (bytes)

# --- Server Identity ---
# Don't disclose gunicorn version in Server header.
# Combined with Flask's header stripping, no version info is exposed.
server_software = ''

# --- Logging ---
# Access log format: timestamp, IP, method, path, status, response time.
# Excludes: request bodies, cookies, and authorization headers.
accesslog = '-'  # stdout (captured by Docker logging)
errorlog = '-'   # stderr (captured by Docker logging)
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" %(L)s'
loglevel = os.environ.get('LOG_LEVEL', 'info')

# --- Process Naming ---
proc_name = 'secure-login-portal'

# --- Forwarded Headers ---
# Trust X-Forwarded-* headers from the reverse proxy.
# IMPORTANT: Only enable when behind a trusted proxy (nginx, ALB, etc.).
# Without a proxy, an attacker could spoof these headers.
forwarded_allow_ips = os.environ.get('FORWARDED_ALLOW_IPS', '127.0.0.1')
