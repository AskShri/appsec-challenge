"""
Flask extension instances — created here, initialized in the app factory.

This pattern (separate from __init__.py) prevents circular imports
and allows extensions to be imported independently by blueprints.
"""

from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
from flask_wtf.csrf import CSRFProtect

# Password hashing — bcrypt with configurable rounds (see config.py).
bcrypt = Bcrypt()

# CSRF protection — validates tokens on all POST/PUT/DELETE requests.
csrf = CSRFProtect()

# Server-side session management — replaces Flask's default client-side sessions.
sess = Session()

# Rate limiting — per-IP by default, per-account on login endpoint.
# key_func=get_remote_address uses the client IP as the default rate limit key.
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri='memory://',
)
