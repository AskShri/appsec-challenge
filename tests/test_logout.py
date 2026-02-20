"""
Tests for logout functionality.

Covers: session clearing, redirect, POST-only enforcement,
and flash message display.
"""


class TestLogout:
    """Tests for the logout endpoint."""

    def test_logout_clears_session(self, authenticated_client):
        """Logout should clear all session data."""
        with authenticated_client:
            authenticated_client.post('/logout')

            from flask import session
            assert 'user_email' not in session

    def test_logout_redirects_to_login(self, authenticated_client):
        """Logout should redirect to the login page."""
        response = authenticated_client.post('/logout', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.headers['Location']

    def test_logout_shows_confirmation_message(self, authenticated_client):
        """Logout should display a confirmation flash message."""
        response = authenticated_client.post('/logout', follow_redirects=True)
        assert b'logged out successfully' in response.data

    def test_logout_get_not_allowed(self, client):
        """GET /logout should return 405 (POST-only for CSRF protection)."""
        # Login first.
        client.post('/login', data={
            'email': 'demo@xero.com',
            'password': 'SecureP@ss123!',
        })
        response = client.get('/logout')
        assert response.status_code == 405
