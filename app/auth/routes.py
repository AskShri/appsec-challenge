"""
Authentication routes — login, logout, dashboard.

Request flow (login POST):
1. Rate limiter (flask-limiter decorator) — outer perimeter
2. CSRF validation (flask-wtf before_request hook) — before we see the request
3. WTForms validation — input constraints
4. Timing-safe credential verification — bcrypt ALWAYS runs
5. Lockout check — AFTER bcrypt for timing consistency
6. Success/failure handling with audit logging

See DESIGN.md §2 for the full request lifecycle diagram.
"""

import uuid
from datetime import datetime, timezone
from functools import wraps

from flask import (
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.auth import auth_bp
from app.auth.forms import LoginForm
from app.auth.models import (
    is_account_locked,
    record_failed_attempt,
    reset_login_attempts,
)
from app.auth.security import (
    log_account_locked,
    log_login_failed,
    log_login_success,
    log_logout,
    verify_credentials,
)
from app.extensions import limiter


# --- Decorators ---

def login_required(f):
    """
    Decorator that ensures the user is authenticated.

    Redirects to the login page if no valid session exists.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


# --- Request Hooks ---

@auth_bp.before_app_request
def set_request_id() -> None:
    """
    Generate a unique request ID for log correlation.

    Allows tracing a single request across all log entries.
    """
    g.request_id = str(uuid.uuid4())[:8]  # Short ID — enough for log correlation


# --- Routes ---

@auth_bp.route('/')
def index():
    """Redirect root to login page."""
    return redirect(url_for('auth.login'))


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit(  # Layer 1: per-IP rate limit (stops single-source automation)
    lambda: current_app.config.get('LOGIN_RATE_LIMIT_IP', '10/minute'),
    methods=['POST'],  # GET requests are exempt — only limit authentication attempts
    error_message='Too many login attempts. Please wait a moment and try again.',
)
@limiter.limit(  # Layer 2: per-account rate limit (stops distributed attacks on one email)
    lambda: current_app.config.get('LOGIN_RATE_LIMIT_ACCOUNT', '5/minute'),
    key_func=lambda: request.form.get('email', '').strip().lower() or request.remote_addr,  # Rate limit key = normalized email
    methods=['POST'],
    error_message='Too many login attempts for this account. Please wait a moment.',
)
def login():
    """
    Login view — handles both GET (render form) and POST (authenticate).

    Security controls applied at this endpoint:
    - Rate limiting: Per-IP (10/min) and per-account (5/min) via decorators
    - CSRF: Validated by flask-wtf before_request hook (before this code runs)
    - Input validation: WTForms validators on email and password fields
    - Timing-safe verification: bcrypt always runs, even for non-existent users
    - Account lockout: Progressive lockout after 5 failed attempts
    - Generic errors: Never reveals whether email exists
    """
    # If already logged in, redirect to dashboard.
    if 'user_email' in session:
        return redirect(url_for('auth.dashboard'))

    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data.strip().lower()  # Normalize to prevent bypass via casing
        password = form.password.data

        # Step 1: ALWAYS run bcrypt verification (~250ms).
        # This MUST happen before the lockout check to prevent timing leaks.
        # If we checked lockout first, locked accounts would respond instantly
        # (~0ms) while unlocked accounts take ~250ms, revealing lockout state.
        credentials_valid = verify_credentials(email, password)

        # Step 2: Check lockout AFTER bcrypt (timing-consistent).
        if is_account_locked(email):
            log_login_failed(email, reason='account_locked')
            # Generic message — doesn't confirm the email exists.
            flash('Too many failed attempts. Please try again later.', 'error')
            return render_template('login.html', form=form), 200

        # Step 3: Handle authentication result.
        if credentials_valid:
            # --- Successful Login ---

            # Session fixation prevention: clear old session data and
            # create a new session ID before storing authenticated state.
            # Per OWASP ASVS V3.2.1.
            session.clear()

            # Store session data.
            session['user_email'] = email
            session['login_time'] = datetime.now(timezone.utc).isoformat()
            session['login_ip'] = request.remote_addr
            session.permanent = True  # Activates PERMANENT_SESSION_LIFETIME (30min idle timeout)

            # Reset lockout counters on successful login.
            reset_login_attempts(email)

            log_login_success(email)

            return redirect(url_for('auth.dashboard'))

        else:
            # --- Failed Login ---

            # Record the failed attempt and get lockout state.
            result = record_failed_attempt(email)

            if result['locked']:
                log_account_locked(email)
                flash('Too many failed attempts. Please try again later.', 'error')
            else:
                log_login_failed(email)

                # Generic error — NEVER "User not found" or "Wrong password".
                # Per OWASP ASVS V2.2.1 and NIST SP 800-63B §5.1.1.
                flash('Invalid email or password.', 'error')

                # Warning before lockout: after LOCKOUT_WARNING_AFTER failures,
                # show a warning. This is safe because it appears for ANY email
                # (we track all emails, not just registered ones).
                warning_after = current_app.config.get('LOCKOUT_WARNING_AFTER', 3)
                threshold = current_app.config['LOCKOUT_THRESHOLD']
                if result['remaining_attempts'] <= (threshold - warning_after):
                    remaining = result['remaining_attempts']
                    if remaining > 0:
                        flash(
                            f'Warning: {remaining} attempt(s) remaining before temporary lockout.',
                            'warning',
                        )

            return render_template('login.html', form=form), 200

    # GET request or form validation failed — render the login form.
    return render_template('login.html', form=form)


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """
    Logout endpoint — POST-only to prevent CSRF via GET.

    Per OWASP ASVS V3.3.1: server-side session invalidation.
    A GET-based logout would allow an attacker to force logout via
    <img src="/logout"> embedded in any page.
    """
    email = session.get('user_email', 'unknown')  # Capture before clearing for audit log

    # Clear all server-side session data.
    session.clear()  # Server-side invalidation — session file is deleted, not just cookie

    log_logout(email)

    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/dashboard')
@login_required
def dashboard():
    """
    Dashboard — displayed after successful authentication.

    Proves that sessions work: shows the authenticated user's identity
    and login time.
    """
    return render_template(
        'dashboard.html',
        user_email=session.get('user_email'),
        login_time=session.get('login_time'),
    )
