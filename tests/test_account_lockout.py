"""
Tests for account lockout functionality.

Covers: lockout threshold, progressive delays, reset on success,
non-existent email tracking, and lockout message safety.
"""


class TestLockoutThreshold:
    """Tests for the 5-attempt lockout trigger."""

    def test_lockout_after_threshold(self, client, app):
        """Account should lock after LOCKOUT_THRESHOLD failed attempts."""
        threshold = app.config['LOCKOUT_THRESHOLD']

        # Exhaust all attempts.
        for i in range(threshold):
            client.post('/login', data={
                'email': 'demo@xero.com',
                'password': 'wrongpassword',
            })

        # Next attempt should show lockout message.
        response = client.post('/login', data={
            'email': 'demo@xero.com',
            'password': 'wrongpassword',
        })
        assert b'Too many failed attempts' in response.data

    def test_under_threshold_not_locked(self, client, app):
        """Attempts under the threshold should not trigger lockout."""
        threshold = app.config['LOCKOUT_THRESHOLD']

        for i in range(threshold - 1):
            response = client.post('/login', data={
                'email': 'demo@xero.com',
                'password': 'wrongpassword',
            })
            assert b'Invalid email or password' in response.data

    def test_lockout_message_is_generic(self, client, app):
        """Lockout message must not reveal whether the email exists."""
        threshold = app.config['LOCKOUT_THRESHOLD']

        for i in range(threshold):
            client.post('/login', data={
                'email': 'demo@xero.com',
                'password': 'wrongpassword',
            })

        response = client.post('/login', data={
            'email': 'demo@xero.com',
            'password': 'wrongpassword',
        })

        # Must not reveal the account exists.
        assert b'Too many failed attempts' in response.data
        assert b'account' not in response.data.lower()


class TestNonExistentEmailTracking:
    """Tests that lockout works for non-existent emails too."""

    def test_nonexistent_email_tracks_attempts(self, client, app):
        """
        Lockout must track non-existent emails to prevent enumeration.

        If we only locked existing accounts, an attacker could distinguish
        existing from non-existing emails by whether lockout triggers.
        """
        threshold = app.config['LOCKOUT_THRESHOLD']

        for i in range(threshold):
            client.post('/login', data={
                'email': 'attacker-target@example.com',
                'password': 'probe',
            })

        response = client.post('/login', data={
            'email': 'attacker-target@example.com',
            'password': 'probe',
        })
        assert b'Too many failed attempts' in response.data


class TestLockoutReset:
    """Tests for lockout counter reset on successful login."""

    def test_reset_on_successful_login(self, client, app):
        """Successful login should reset the failed attempt counter."""
        # Accumulate some failures (under threshold).
        for i in range(3):
            client.post('/login', data={
                'email': 'demo@xero.com',
                'password': 'wrongpassword',
            })

        # Successful login.
        client.post('/login', data={
            'email': 'demo@xero.com',
            'password': 'SecureP@ss123!',
        })

        # Logout.
        client.post('/logout')

        # Should be able to fail again without hitting lockout
        # (counter was reset).
        for i in range(3):
            response = client.post('/login', data={
                'email': 'demo@xero.com',
                'password': 'wrongpassword',
            })
            assert b'Invalid email or password' in response.data


class TestLockoutWarning:
    """Tests for the pre-lockout warning message."""

    def test_warning_shown_before_lockout(self, client, app):
        """A warning should appear after LOCKOUT_WARNING_AFTER failures."""
        warning_after = app.config.get('LOCKOUT_WARNING_AFTER', 3)

        # Fail enough times to trigger the warning.
        for i in range(warning_after + 1):
            response = client.post('/login', data={
                'email': 'demo@xero.com',
                'password': 'wrongpassword',
            })

        assert b'attempt' in response.data.lower()
