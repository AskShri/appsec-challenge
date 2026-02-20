"""
Security response headers middleware.

Applied via @app.after_request to EVERY response. Each header is
documented with the threat it mitigates.

Why manual instead of flask-talisman?
- flask-talisman is unmaintained (see DECISIONS.md ADR-2)
- Manual implementation demonstrates understanding of each header
- Full control over nonce-based CSP
"""

import secrets

from flask import Flask, g, request


def generate_csp_nonce() -> str:
    """
    Generate a cryptographically random nonce for Content Security Policy.

    32 bytes = 256 bits of entropy, base64url-encoded.
    A new nonce is generated per-request to prevent nonce reuse.
    """
    return secrets.token_urlsafe(32)


def init_security_headers(app: Flask) -> None:
    """Register security header hooks on the Flask app."""

    @app.before_request
    def set_csp_nonce() -> None:
        """Generate a per-request CSP nonce and store in Flask's g object."""
        g.csp_nonce = generate_csp_nonce()

    @app.context_processor
    def inject_csp_nonce() -> dict:
        """Make the CSP nonce available in all Jinja2 templates."""
        return {'csp_nonce': g.get('csp_nonce', '')}

    @app.after_request
    def set_security_headers(response):
        """
        Apply security headers to every response.

        Headers are ordered by the threat they mitigate for readability.
        """
        nonce = g.get('csp_nonce', '')

        # --- XSS Protection ---

        # Content-Security-Policy: Nonce-based policy.
        # Only scripts/styles with the correct nonce can execute.
        # - default-src 'self': Only load resources from same origin
        # - script-src 'nonce-...': Only scripts with this nonce execute
        # - style-src 'self' 'nonce-...': Same-origin styles + nonce for inline
        # - img-src 'self': Only same-origin images
        # - frame-ancestors 'none': Prevents clickjacking (CSP-level)
        # - form-action 'self': Prevents form action injection
        # - base-uri 'self': Prevents <base> tag injection
        # - object-src 'none': Blocks Flash/Java plugins (XSS vector)
        csp_directives = [
            "default-src 'self'",
            f"script-src 'nonce-{nonce}'",
            f"style-src 'self' 'nonce-{nonce}'",
            "img-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'self'",
            "object-src 'none'",
        ]
        response.headers['Content-Security-Policy'] = '; '.join(csp_directives)

        # X-Content-Type-Options: Prevents MIME-type confusion attacks.
        # Without this, browsers might execute a file as JavaScript
        # based on content sniffing even if Content-Type says otherwise.
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # --- Clickjacking Protection ---

        # X-Frame-Options: Legacy clickjacking protection (for older browsers).
        # CSP frame-ancestors is the modern equivalent, but we set both
        # for defense-in-depth across browser versions.
        response.headers['X-Frame-Options'] = 'DENY'

        # --- Transport Security ---

        # Strict-Transport-Security: Forces HTTPS for all future requests.
        # max-age=31536000 = 1 year. includeSubDomains covers all subdomains.
        # Only set in non-debug mode to avoid HSTS issues during local development.
        if not app.debug:
            response.headers['Strict-Transport-Security'] = (
                'max-age=31536000; includeSubDomains'
            )

        # --- Privacy & Information Leakage ---

        # Referrer-Policy: Controls how much URL info is sent in Referer header.
        # 'strict-origin-when-cross-origin' sends only the origin (not full URL)
        # on cross-origin requests, preventing leakage of sensitive URL paths.
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Permissions-Policy: Explicitly disable browser features we don't use.
        # Reduces attack surface — even if XSS executes, it can't access
        # camera, microphone, geolocation, or payment APIs.
        response.headers['Permissions-Policy'] = (
            'camera=(), microphone=(), geolocation=(), payment=()'
        )

        # Cross-Origin-Opener-Policy: Prevents cross-origin windows from
        # getting a reference to our window object (mitigates Spectre-type attacks).
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'

        # Cross-Origin-Resource-Policy: Prevents other origins from loading
        # our resources (images, scripts, etc.) — reduces data exfiltration risk.
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'

        # X-Permitted-Cross-Domain-Policies: Prevents Adobe Flash/PDF
        # crossdomain.xml policy files from granting access.
        response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'

        # --- Caching ---

        # Cache-Control: Prevent caching of authenticated pages.
        # Login pages and dashboards must not be cached — a shared computer
        # user could hit "Back" and see a previous user's session.
        # Only apply to non-static resources (CSS/JS can be cached).
        if not request.path.startswith('/static/'):
            response.headers['Cache-Control'] = (
                'no-store, no-cache, must-revalidate, max-age=0'
            )
            # Pragma: HTTP/1.0 fallback for no-cache behavior.
            response.headers['Pragma'] = 'no-cache'

        # --- Version Disclosure ---

        # Remove server identification headers to prevent version fingerprinting.
        # Attackers use version info to look up known vulnerabilities.
        response.headers.pop('Server', None)
        response.headers.pop('X-Powered-By', None)

        return response
