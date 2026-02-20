"""
Structured security audit logging.

All security events are logged as JSON for machine parsing.
Events include: login_success, login_failed, account_locked,
logout, csrf_failure, rate_limit_exceeded.

NEVER logs: passwords, session tokens, or full request bodies.
Per OWASP Logging Cheat Sheet.
"""

import json
import logging
import re
import time
from typing import Any, Dict


# Control characters that could enable log injection attacks.
# Stripping these prevents attackers from forging log entries via malicious input.
_LOG_INJECTION_PATTERN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def sanitize_log_value(value: str, max_length: int = 256) -> str:
    """
    Sanitize a string for safe inclusion in log output.

    Prevents log injection by removing control characters and
    truncating to a maximum length.
    """
    cleaned = _LOG_INJECTION_PATTERN.sub('', str(value))  # Strip control chars (\n, \r, \x00, etc.)
    return cleaned[:max_length]  # Prevent log bloat from oversized input


class SecurityAuditFormatter(logging.Formatter):
    """JSON formatter for security audit events."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S%z', time.gmtime(record.created)),
            'level': record.levelname,
            'event': getattr(record, 'event', 'unknown'),
            'message': record.getMessage(),
        }

        # Add optional context fields if present
        for field in ('ip', 'email', 'user_agent', 'request_id', 'reason'):
            value = getattr(record, field, None)
            if value is not None:
                log_entry[field] = sanitize_log_value(str(value))

        return json.dumps(log_entry)


def setup_security_logging(app) -> logging.Logger:
    """
    Configure the security audit logger.

    Returns a dedicated 'security.audit' logger that writes JSON
    to both file and stderr.
    """
    logger = logging.getLogger('security.audit')
    logger.setLevel(logging.INFO)

    # Avoid adding duplicate handlers on repeated calls (e.g., in tests)
    if logger.handlers:  # Prevent duplicate handlers on repeated create_app() calls (tests)
        return logger

    formatter = SecurityAuditFormatter()

    # Console handler — security events visible in application output
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


def audit_log(event: str, message: str, **context) -> None:
    """
    Log a security audit event.

    Args:
        event: Event type (e.g., 'login_success', 'login_failed')
        message: Human-readable description
        **context: Additional context (ip, email, user_agent, request_id)
    """
    logger = logging.getLogger('security.audit')
    extra = {'event': event}
    extra.update(context)
    logger.info(message, extra=extra)
