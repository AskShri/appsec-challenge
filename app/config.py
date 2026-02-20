"""
Application configuration — all security thresholds in one place.

Every threshold includes a comment explaining WHY that value was chosen.
No magic numbers.
"""

import os
import secrets


class BaseConfig:
    """Shared configuration for all environments."""

    # --- Flask Core ---
    # 256-bit random secret for session signing and CSRF tokens.
    # Generated once per deployment; in production, load from environment variable.
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    # Reject request bodies larger than 16KB.
    # Login forms are ~200 bytes; anything larger is suspicious (DoS prevention).
    MAX_CONTENT_LENGTH = 16 * 1024  # 16KB

    # --- Session Configuration (flask-session) ---
    # Server-side filesystem sessions — cookie contains only an opaque ID.
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = True
    # 30-minute idle timeout per OWASP ASVS V3.3.2.
    PERMANENT_SESSION_LIFETIME = 1800  # seconds
    SESSION_USE_SIGNER = True  # Sign the session ID cookie
    SESSION_KEY_PREFIX = 'session:'

    # --- Session Cookie Flags ---
    SESSION_COOKIE_HTTPONLY = True    # Prevents JavaScript access (XSS mitigation)
    SESSION_COOKIE_SAMESITE = 'Lax'  # Prevents CSRF via cross-origin requests
    SESSION_COOKIE_NAME = 'session'

    # --- bcrypt ---
    # 12 rounds ≈ 250ms per hash. Balances security (expensive for attackers)
    # vs. UX (imperceptible latency for legitimate users).
    # OWASP minimum is 10; we use 12 for additional margin.
    BCRYPT_LOG_ROUNDS = 12

    # --- Rate Limiting (flask-limiter) ---
    RATELIMIT_ENABLED = True
    # In-memory storage for single-instance deployment.
    # Production: use Redis ("redis://localhost:6379")
    RATELIMIT_STORAGE_URI = 'memory://'
    # Include rate limit headers so clients/monitoring can observe limits.
    RATELIMIT_HEADERS_ENABLED = True
    # Global default — generous limit for non-login endpoints.
    RATELIMIT_DEFAULT = '200/hour'

    # --- Login-Specific Rate Limits ---
    # Per-IP: 10 attempts/minute. Stops fast automated attacks from single source.
    # Generous enough that a legitimate user mistyping won't hit it.
    LOGIN_RATE_LIMIT_IP = '10/minute'
    # Per-account: 5 attempts/minute. Stops distributed attacks targeting one email.
    LOGIN_RATE_LIMIT_ACCOUNT = '5/minute'

    # --- Account Lockout ---
    # After 5 failed attempts, account is locked.
    # Balances security (stops brute force) vs. UX (won't lock out on 2-3 typos).
    LOCKOUT_THRESHOLD = 5
    # Progressive lockout durations in seconds: 1min → 5min → 15min → 1hr.
    # Progressive approach is less punishing than permanent lockout
    # while still making brute force impractical.
    LOCKOUT_DURATIONS = [60, 300, 900, 3600]
    # Show warning after this many failures (before lockout threshold).
    # "Multiple failed attempts detected" — safe because it appears for ANY email.
    LOCKOUT_WARNING_AFTER = 3

    # --- Database ---
    # SQLite database in Flask's instance folder.
    # Production: PostgreSQL with connection pooling (see DECISIONS.md ADR-5).
    DATABASE_NAME = 'app.db'


class ProductionConfig(BaseConfig):
    """Production environment — all security controls enforced."""

    DEBUG = False
    TESTING = False

    # SECRET_KEY MUST be set via environment variable in production.
    # Fail loudly if missing — never fall back to a random key
    # (random key would invalidate all sessions on restart).
    SECRET_KEY = os.environ.get('SECRET_KEY')

    # --- Cookie Security (requires HTTPS) ---
    SESSION_COOKIE_SECURE = True       # Cookie only sent over HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # --- Proxy Awareness ---
    # When behind a reverse proxy (nginx), trust X-Forwarded-For for rate limiting.
    # Set to the number of proxies in front of the app (typically 1).
    PROXY_COUNT = int(os.environ.get('PROXY_COUNT', '1'))

    @classmethod
    def init_app(cls, app):
        """Validate required configuration at startup."""
        if not cls.SECRET_KEY:
            raise RuntimeError(
                'SECRET_KEY environment variable is required in production. '
                'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
            )


class DevelopmentConfig(BaseConfig):
    """Development environment — relaxed cookie settings for HTTP."""

    DEBUG = True
    # Allow cookies over HTTP during local development.
    SESSION_COOKIE_SECURE = False
    # Show where sessions are stored on startup.
    EXPLAIN_TEMPLATE_LOADING = False


class TestConfig(BaseConfig):
    """Test environment — fast bcrypt, CSRF/rate-limiting off by default."""

    TESTING = True
    SESSION_COOKIE_SECURE = False
    # 4 rounds for fast test execution (~4ms vs ~250ms per hash).
    BCRYPT_LOG_ROUNDS = 4
    # Disable rate limiting and CSRF by default in tests.
    # Specific test files enable them via dedicated config classes.
    RATELIMIT_ENABLED = False
    WTF_CSRF_ENABLED = False
    # Use separate database for tests
    DATABASE_NAME = 'test.db'


class RateLimitTestConfig(TestConfig):
    """Test config with rate limiting enabled."""

    RATELIMIT_ENABLED = True


class CSRFTestConfig(TestConfig):
    """Test config with CSRF protection enabled."""

    WTF_CSRF_ENABLED = True
