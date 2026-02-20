"""
Tests for CSRF protection.

Uses CSRFTestConfig which enables flask-wtf CSRFProtect.
"""

import re


class TestCSRFProtection:
    """Tests for CSRF token validation."""

    def test_post_without_csrf_token_fails(self, csrf_client):
        """POST without a CSRF token should be rejected."""
        response = csrf_client.post('/login', data={
            'email': 'demo@xero.com',
            'password': 'SecureP@ss123!',
        }, follow_redirects=True)

        # CSRF failure redirects to login with a flash message.
        assert response.status_code == 200  # followed redirect back to login
        assert b'form session has expired' in response.data

    def test_post_with_valid_csrf_token_succeeds(self, csrf_client):
        """POST with a valid CSRF token should proceed normally."""
        # First, GET the login page to obtain a CSRF token.
        get_response = csrf_client.get('/login')
        html = get_response.data.decode()

        # Extract the CSRF token from the hidden field.
        match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
        assert match, 'CSRF token not found in form'
        csrf_token = match.group(1)

        # POST with the valid token.
        response = csrf_client.post('/login', data={
            'email': 'demo@xero.com',
            'password': 'SecureP@ss123!',
            'csrf_token': csrf_token,
        }, follow_redirects=False)

        # Should succeed (redirect to dashboard, not blocked by CSRF).
        assert response.status_code == 302
        assert '/dashboard' in response.headers['Location']

    def test_csrf_token_in_login_form(self, csrf_client):
        """Login form should contain a CSRF token hidden field."""
        response = csrf_client.get('/login')
        html = response.data.decode()
        assert 'csrf_token' in html

    def test_csrf_token_in_logout_form(self, csrf_client):
        """Logout form on dashboard should contain a CSRF token."""
        # Login first.
        get_response = csrf_client.get('/login')
        html = get_response.data.decode()
        match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
        csrf_token = match.group(1)

        csrf_client.post('/login', data={
            'email': 'demo@xero.com',
            'password': 'SecureP@ss123!',
            'csrf_token': csrf_token,
        })

        # Check dashboard has CSRF token in logout form.
        response = csrf_client.get('/dashboard')
        assert b'csrf_token' in response.data
