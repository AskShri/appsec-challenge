"""
Flask application factory.

Creates and configures the Flask app with all security extensions,
middleware, and blueprints. Uses the factory pattern for testability —
each test can create an app with a different config class.

Extension initialization order:
1. bcrypt — needed by models for password hashing during init_db
2. csrf — registers before_request hook for CSRF validation
3. session — server-side session management
4. limiter — conditional on RATELIMIT_ENABLED config

See DESIGN.md §1 for the architecture overview.
"""

import os

from flask import Flask, g, render_template

from app.config import DevelopmentConfig


def create_app(config_class=None):
    """
    Create and configure the Flask application.

    Args:
        config_class: Configuration class to use. Defaults to DevelopmentConfig.
                      Tests pass TestConfig, RateLimitTestConfig, etc.

    Returns:
        Configured Flask application instance.
    """
    if config_class is None:
        config_class = DevelopmentConfig

    app = Flask(
        __name__,
        static_folder='static',
        static_url_path='/static',
    )
    app.config.from_object(config_class)

    # Ensure the instance folder exists (for SQLite database and sessions).
    os.makedirs(app.instance_path, exist_ok=True)

    # Configure session file directory inside instance folder.
    # Default /tmp/flask_session doesn't exist on Windows.
    session_dir = os.path.join(app.instance_path, 'flask_sessions')
    os.makedirs(session_dir, exist_ok=True)
    app.config['SESSION_FILE_DIR'] = session_dir  # Override default /tmp (doesn't exist on Windows)

    # --- Initialize Extensions ---
    # Order matters: bcrypt must be ready before init_db seeds the demo user.

    from app.extensions import bcrypt, csrf, limiter, sess

    bcrypt.init_app(app)
    csrf.init_app(app)
    sess.init_app(app)

    # Conditionally enable rate limiting.
    # Disabled in most tests (TestConfig) for speed; enabled in RateLimitTestConfig.
    if app.config.get('RATELIMIT_ENABLED', True):
        limiter.init_app(app)
        # Update storage URI from config
        limiter._storage_uri = app.config.get('RATELIMIT_STORAGE_URI', 'memory://')
    else:
        # Register a no-op limiter so @limiter.limit decorators don't error.
        limiter.init_app(app)
        limiter.enabled = False  # Decorators remain but skip enforcement

    # --- Security Headers ---
    from app.headers import init_security_headers
    init_security_headers(app)

    # --- Logging ---
    from app.logging_config import setup_security_logging
    setup_security_logging(app)

    # --- Initialize Dummy Hash for Timing-Safe Verification ---
    from app.auth.security import init_dummy_hash
    with app.app_context():  # bcrypt needs app context for BCRYPT_LOG_ROUNDS config
        init_dummy_hash(app)

    # --- Register Blueprints ---
    from app.auth import auth_bp
    app.register_blueprint(auth_bp)

    # --- CSRF Error Handler ---
    from flask_wtf.csrf import CSRFError
    from app.auth.security import log_csrf_failure

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        """
        Handle CSRF token validation failures gracefully.

        Shows a user-friendly message instead of a raw 400 error.
        The user simply needs to reload the form to get a fresh token.
        """
        log_csrf_failure()
        from flask import flash, redirect, url_for
        flash('Your form session has expired. Please try again.', 'warning')
        return redirect(url_for('auth.login'))

    # --- HTTP Error Handlers ---

    @app.errorhandler(429)
    def handle_rate_limit(e):
        """Rate limit exceeded — user-friendly page, not a raw error."""
        return render_template('errors/429.html'), 429

    @app.errorhandler(404)
    def handle_not_found(e):
        """Page not found."""
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def handle_server_error(e):
        """Internal server error — no stack traces or internal details."""
        return render_template('errors/500.html'), 500

    @app.errorhandler(413)
    def handle_request_too_large(e):
        """Request body exceeds MAX_CONTENT_LENGTH (16KB)."""
        return render_template('errors/413.html'), 413

    # --- Database Initialization ---
    from app.auth.models import close_db, init_db

    # Register teardown to close DB connections at the end of each request.
    app.teardown_appcontext(close_db)  # Auto-close DB connection at end of every request

    # Initialize database tables and seed demo user.
    with app.app_context():
        init_db(app)

    return app
