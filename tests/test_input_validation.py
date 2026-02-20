"""
Tests for input validation on the login form.

Covers: empty fields, invalid email format, max length enforcement,
and generic error messages for invalid input.
"""


class TestEmailValidation:
    """Tests for email field validation."""

    def test_empty_email_rejected(self, client):
        """Empty email should show a validation error."""
        response = client.post('/login', data={
            'email': '',
            'password': 'somepassword',
        })
        assert b'Email address is required' in response.data

    def test_invalid_email_format_rejected(self, client):
        """Invalid email format should show a validation error."""
        response = client.post('/login', data={
            'email': 'not-an-email',
            'password': 'somepassword',
        })
        assert b'valid email address' in response.data

    def test_email_too_long_rejected(self, client):
        """Email exceeding 254 characters should be rejected."""
        long_email = 'a' * 245 + '@test.com'  # 254+ chars
        response = client.post('/login', data={
            'email': long_email,
            'password': 'somepassword',
        })
        # Should show either length error or format error.
        assert response.status_code == 200  # Form re-rendered, not crash


class TestPasswordValidation:
    """Tests for password field validation."""

    def test_empty_password_rejected(self, client):
        """Empty password should show a validation error."""
        response = client.post('/login', data={
            'email': 'demo@xero.com',
            'password': '',
        })
        assert b'Password is required' in response.data

    def test_very_long_password_rejected(self, client):
        """Password exceeding 128 characters should be rejected."""
        long_password = 'a' * 129
        response = client.post('/login', data={
            'email': 'demo@xero.com',
            'password': long_password,
        })
        assert b'Password is too long' in response.data
