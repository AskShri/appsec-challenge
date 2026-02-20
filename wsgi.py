"""
WSGI entry point for production deployment (gunicorn).

Usage:
    gunicorn -c gunicorn.conf.py wsgi:app

This module creates the Flask app with ProductionConfig and validates
that all required environment variables are set.
"""

import os
import sys

from app.config import ProductionConfig

# Validate production config before creating the app.
# Fail fast with a clear error message if SECRET_KEY is missing.
if not ProductionConfig.SECRET_KEY:
    print(
        'FATAL: SECRET_KEY environment variable is required.\n'
        'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"',
        file=sys.stderr,
    )
    sys.exit(1)

from app import create_app

app = create_app(config_class=ProductionConfig)
