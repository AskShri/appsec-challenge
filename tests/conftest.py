"""
Pytest fixtures for the secure login portal test suite.

Provides multiple app configurations for testing different security
controls in isolation:
- app/client: Base test config (CSRF off, rate limiting off)
- csrf_app/csrf_client: CSRF enabled
- rate_limit_app/rate_limit_client: Rate limiting enabled
"""

import os
import shutil
import tempfile

import pytest

from app import create_app
from app.config import CSRFTestConfig, RateLimitTestConfig, TestConfig


@pytest.fixture
def app(tmp_path):
    """Create a Flask app with the base test configuration."""
    # Override instance path to use a temp directory per test.
    app = create_app(TestConfig)
    app.instance_path = str(tmp_path)

    # Ensure session directory exists.
    session_dir = os.path.join(str(tmp_path), 'flask_sessions')
    os.makedirs(session_dir, exist_ok=True)
    app.config['SESSION_FILE_DIR'] = session_dir

    # Re-init database in the temp directory.
    app.config['DATABASE_NAME'] = 'test.db'
    from app.auth.models import init_db
    with app.app_context():
        init_db(app)

    yield app


@pytest.fixture
def client(app):
    """Test client for the base app configuration."""
    return app.test_client()


@pytest.fixture
def csrf_app(tmp_path):
    """Create a Flask app with CSRF protection enabled."""
    app = create_app(CSRFTestConfig)
    app.instance_path = str(tmp_path)

    session_dir = os.path.join(str(tmp_path), 'flask_sessions')
    os.makedirs(session_dir, exist_ok=True)
    app.config['SESSION_FILE_DIR'] = session_dir

    app.config['DATABASE_NAME'] = 'test.db'
    from app.auth.models import init_db
    with app.app_context():
        init_db(app)

    yield app


@pytest.fixture
def csrf_client(csrf_app):
    """Test client with CSRF protection enabled."""
    return csrf_app.test_client()


@pytest.fixture
def rate_limit_app(tmp_path):
    """Create a Flask app with rate limiting enabled."""
    app = create_app(RateLimitTestConfig)
    app.instance_path = str(tmp_path)

    session_dir = os.path.join(str(tmp_path), 'flask_sessions')
    os.makedirs(session_dir, exist_ok=True)
    app.config['SESSION_FILE_DIR'] = session_dir

    app.config['DATABASE_NAME'] = 'test.db'
    from app.auth.models import init_db
    with app.app_context():
        init_db(app)

    yield app


@pytest.fixture
def rate_limit_client(rate_limit_app):
    """Test client with rate limiting enabled."""
    return rate_limit_app.test_client()


@pytest.fixture
def authenticated_client(app, client):
    """Test client that is already logged in."""
    client.post('/login', data={
        'email': 'demo@xero.com',
        'password': 'SecureP@ss123!',
    })
    return client
