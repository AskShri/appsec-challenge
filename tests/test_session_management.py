"""
Tests for secure session management.

Covers: cookie flags, session regeneration on login,
session invalidation on logout, and login_required enforcement.
"""


class TestSessionCookieFlags:
    """Tests for session cookie security attributes."""

    def test_session_cookie_httponly(self, app, client):
        """Session cookie must have HttpOnly flag (prevents XSS access)."""
        response = client.post('/login', data={
            'email': 'demo@xero.com',
            'password': 'SecureP@ss123!',
        })

        # Verify HttpOnly is configured at the application level.
        # The Set-Cookie header should contain HttpOnly when the cookie is set.
        assert app.config['SESSION_COOKIE_HTTPONLY'] is True

        # Check the Set-Cookie header in the response for HttpOnly flag.
        set_cookie_headers = response.headers.getlist('Set-Cookie')
        session_cookies = [h for h in set_cookie_headers if 'session=' in h.lower() or 'session:' in h.lower()]
        if session_cookies:
            # At least one session cookie header should have HttpOnly
            assert any('httponly' in c.lower() for c in session_cookies), \
                'Session cookie missing HttpOnly flag'

    def test_session_cookie_samesite(self, app):
        """Session cookie must have SameSite=Lax (CSRF mitigation)."""
        assert app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'


class TestSessionLifecycle:
    """Tests for session creation and destruction."""

    def test_session_created_on_login(self, client):
        """Login should create a session with user identity."""
        with client:
            client.post('/login', data={
                'email': 'demo@xero.com',
                'password': 'SecureP@ss123!',
            })

            from flask import session
            assert session['user_email'] == 'demo@xero.com'
            assert 'login_time' in session
            assert 'login_ip' in session

    def test_session_cleared_on_logout(self, authenticated_client):
        """Logout must clear all session data (server-side invalidation)."""
        with authenticated_client:
            authenticated_client.post('/logout')

            from flask import session
            assert 'user_email' not in session

    def test_session_regeneration_on_login(self, client):
        """
        Login must regenerate the session ID (session fixation prevention).

        Verifies that session.clear() is called before setting new data,
        which causes flask-session to create a new session file/ID.
        """
        # Set a value in the pre-login session.
        with client.session_transaction() as sess:
            sess['pre_login_marker'] = 'should_be_cleared'

        # Login — should clear old session and create new one.
        with client:
            client.post('/login', data={
                'email': 'demo@xero.com',
                'password': 'SecureP@ss123!',
            })

            from flask import session
            # The pre-login marker should be gone (session was cleared).
            assert 'pre_login_marker' not in session
            # New session data should be present.
            assert session['user_email'] == 'demo@xero.com'


class TestLoginRequired:
    """Tests for the login_required decorator."""

    def test_dashboard_requires_login(self, client):
        """Accessing dashboard without login should redirect to login."""
        response = client.get('/dashboard', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.headers['Location']

    def test_dashboard_accessible_when_logged_in(self, authenticated_client):
        """Dashboard should be accessible with a valid session."""
        response = authenticated_client.get('/dashboard')
        assert response.status_code == 200
        assert b'Welcome' in response.data

    def test_logout_requires_login(self, client):
        """Logout without a session should redirect to login."""
        response = client.post('/logout', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.headers['Location']
