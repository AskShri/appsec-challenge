"""
Security utilities — timing-safe credential verification and audit helpers.

This module contains the core security logic that protects against:
- Timing-based user enumeration (dummy hash technique)
- Information leakage through error messages
- Unaudited security events

References:
- OWASP ASVS V2.2.1 (anti-automation)
- NIST SP 800-63B §5.2.2 (credential verification)
"""

from flask import current_app, request, g

from app.extensions import bcrypt
from app.logging_config import audit_log, sanitize_log_value


# --- Timing-Safe Credential Verification ---

# Pre-computed dummy hash used when the requested email doesn't exist.
# By running bcrypt.check_password_hash against this dummy hash for
# non-existent users, we ensure the response time is identical regardless
# of whether the email exists. Without this, an attacker could measure
# response times: fast response = email doesn't exist (no bcrypt work),
# slow response = email exists (bcrypt ran against real hash).
#
# This hash is generated at module load time with the same cost factor
# as production hashes. The actual password value doesn't matter —
# we only care about the ~250ms bcrypt execution time.
from typing import Optional

DUMMY_HASH: Optional[str] = None


def init_dummy_hash(app) -> None:
    """
    Initialize the dummy hash within an app context.

    Called during app factory initialization so bcrypt has access
    to the configured cost factor.
    """
    global DUMMY_HASH
    DUMMY_HASH = bcrypt.generate_password_hash('dummy_password_for_timing').decode('utf-8')  # Same cost as real hashes


def verify_credentials(email: str, password: str) -> bool:
    """
    Verify credentials in constant time regardless of whether the user exists.

    This function ALWAYS runs bcrypt.check_password_hash, even for
    non-existent users (using DUMMY_HASH). This prevents timing-based
    user enumeration — every login attempt takes ~250ms.

    Args:
        email: Normalized email address.
        password: Plaintext password from the form.

    Returns:
        True if credentials are valid, False otherwise.
        The caller MUST NOT reveal why verification failed.
    """
    from app.auth.models import get_user_by_email  # Deferred import avoids circular dependency

    user = get_user_by_email(email)

    if user is not None:
        # Real user: check against their actual password hash.
        return bcrypt.check_password_hash(user['password_hash'], password)
    else:
        # Non-existent user: check against dummy hash (result is always False).
        # This takes the same ~250ms as a real check, preventing timing leaks.
        bcrypt.check_password_hash(DUMMY_HASH, password)  # Burns ~250ms — attacker can't distinguish from real user
        return False  # Always False for non-existent users


def get_request_context() -> dict:
    """
    Extract security-relevant context from the current request.

    Returns:
        dict with ip, user_agent, and request_id for audit logging.
        User-agent is truncated to 200 chars to prevent log bloat from
        crafted UA strings.
    """
    return {
        'ip': request.remote_addr or 'unknown',
        'user_agent': sanitize_log_value(
            request.headers.get('User-Agent', 'unknown'),
            max_length=200,
        ),
        'request_id': g.get('request_id', 'unknown'),
    }


def log_login_success(email: str) -> None:
    """Audit log: successful authentication."""
    ctx = get_request_context()
    audit_log(
        event='login_success',
        message=f'Successful login for {sanitize_log_value(email)}',
        email=sanitize_log_value(email),
        **ctx,
    )


def log_login_failed(email: str, reason: str = 'invalid_credentials') -> None:
    """Audit log: failed authentication attempt."""
    ctx = get_request_context()
    audit_log(
        event='login_failed',
        message=f'Failed login for {sanitize_log_value(email)}: {reason}',
        email=sanitize_log_value(email),
        reason=reason,
        **ctx,
    )


def log_account_locked(email: str) -> None:
    """Audit log: account lockout triggered."""
    ctx = get_request_context()
    audit_log(
        event='account_locked',
        message=f'Account locked for {sanitize_log_value(email)}',
        email=sanitize_log_value(email),
        **ctx,
    )


def log_logout(email: str) -> None:
    """Audit log: user logout."""
    ctx = get_request_context()
    audit_log(
        event='logout',
        message=f'Logout for {sanitize_log_value(email)}',
        email=sanitize_log_value(email),
        **ctx,
    )


def log_csrf_failure() -> None:
    """Audit log: CSRF token validation failure."""
    ctx = get_request_context()
    audit_log(
        event='csrf_failure',
        message='CSRF token validation failed',
        **ctx,
    )
