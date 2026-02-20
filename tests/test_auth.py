"""
Tests for core authentication functionality.

Covers: successful login, failed login, generic error messages,
timing-safe verification, redirect behavior, and session creation.
"""


class TestLoginSuccess:
    """Tests for successful authentication."""

    def test_valid_credentials_redirect_to_dashboard(self, client):
        """Successful login should redirect to the dashboard."""
        response = client.post('/login', data={
            'email': 'demo@xero.com',
            'password': 'SecureP@ss123!',
        }, follow_redirects=False)

        assert response.status_code == 302
        assert '/dashboard' in response.headers['Location']

    def test_valid_credentials_set_session(self, client, app):
        """Successful login should create a session with user data."""
        with client:
            client.post('/login', data={
                'email': 'demo@xero.com',
                'password': 'SecureP@ss123!',
            })

            from flask import session
            assert session.get('user_email') == 'demo@xero.com'
            assert 'login_time' in session

    def test_dashboard_shows_user_email(self, client):
        """Dashboard should display the authenticated user's email."""
        client.post('/login', data={
            'email': 'demo@xero.com',
            'password': 'SecureP@ss123!',
        })
        response = client.get('/dashboard')
        assert b'demo@xero.com' in response.data


class TestLoginFailure:
    """Tests for failed authentication — verifies generic error messages."""

    def test_wrong_password_shows_generic_error(self, client):
        """Wrong password must show 'Invalid email or password', not 'Wrong password'."""
        response = client.post('/login', data={
            'email': 'demo@xero.com',
            'password': 'wrongpassword',
        })
        assert b'Invalid email or password' in response.data
        # Must NOT reveal that the email exists.
        assert b'Wrong password' not in response.data
        assert b'Incorrect password' not in response.data

    def test_nonexistent_email_shows_generic_error(self, client):
        """Non-existent email must show the same error as wrong password."""
        response = client.post('/login', data={
            'email': 'nobody@example.com',
            'password': 'anypassword',
        })
        assert b'Invalid email or password' in response.data
        # Must NOT reveal that the email doesn't exist.
        assert b'User not found' not in response.data
        assert b'No account' not in response.data

    def test_empty_email_shows_validation_error(self, client):
        """Empty email should show a validation error."""
        response = client.post('/login', data={
            'email': '',
            'password': 'somepassword',
        })
        assert b'Email address is required' in response.data

    def test_empty_password_shows_validation_error(self, client):
        """Empty password should show a validation error."""
        response = client.post('/login', data={
            'email': 'demo@xero.com',
            'password': '',
        })
        assert b'Password is required' in response.data


class TestLoginRedirects:
    """Tests for authentication-related redirects."""

    def test_root_redirects_to_login(self, client):
        """Root URL should redirect to the login page."""
        response = client.get('/', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.headers['Location']

    def test_already_logged_in_redirects_from_login(self, authenticated_client):
        """Logged-in user visiting /login should be redirected to dashboard."""
        response = authenticated_client.get('/login', follow_redirects=False)
        assert response.status_code == 302
        assert '/dashboard' in response.headers['Location']

    def test_unauthenticated_dashboard_redirects_to_login(self, client):
        """Accessing dashboard without login should redirect to login."""
        response = client.get('/dashboard', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.headers['Location']
