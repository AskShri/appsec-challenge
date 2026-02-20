"""
Database models — SQLite user store and login attempt tracking.

Uses parameterized queries exclusively (? placeholders) to prevent
SQL injection. Per OWASP ASVS V5.3.4.

Connection management uses Flask's g object for per-request connections,
with check_same_thread=False for Flask's multi-threaded request handling.
"""

import os
import sqlite3
import time
from typing import Optional

from flask import current_app, g


def get_db() -> sqlite3.Connection:
    """
    Get a database connection for the current request.

    Connections are stored in Flask's g object and reused within
    a single request. Closed automatically via teardown_appcontext.

    Uses check_same_thread=False because Flask may handle the request
    across different threads (e.g., teardown on a different thread).
    """
    if 'db' not in g:
        db_path = os.path.join(
            current_app.instance_path,
            current_app.config['DATABASE_NAME'],
        )
        g.db = sqlite3.connect(db_path, check_same_thread=False)
        g.db.row_factory = sqlite3.Row  # Enables dict-like access: row['email']
        g.db.execute('PRAGMA journal_mode=WAL')  # Write-Ahead Logging — better concurrent reads
    return g.db


def close_db(exception=None) -> None:
    """Close the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db(app) -> None:
    """
    Initialize database tables and seed demo user.

    Uses CREATE TABLE IF NOT EXISTS for idempotency — safe to call
    on every app startup without data loss.
    """
    from app.extensions import bcrypt

    db_path = os.path.join(app.instance_path, app.config['DATABASE_NAME'])
    conn = sqlite3.connect(db_path, check_same_thread=False)

    try:
        # Users table — stores credentials.
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                email         TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL DEFAULT (datetime('now'))
            )
        ''')

        # Login attempts table — tracks failed attempts and lockout state.
        # Keyed by email (not user ID) so we can track attempts against
        # non-existent emails too (prevents enumeration via lockout behavior).
        conn.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                email         TEXT PRIMARY KEY,
                attempts      INTEGER NOT NULL DEFAULT 0,
                locked_until  REAL,
                lockout_count INTEGER NOT NULL DEFAULT 0,
                last_attempt  REAL
            )
        ''')

        conn.commit()

        # Seed demo user if the users table is empty.
        cursor = conn.execute('SELECT COUNT(*) FROM users')
        count = cursor.fetchone()[0]

        if count == 0:
            demo_email = 'demo@xero.com'
            demo_password = 'SecureP@ss123!'

            # Hash password using bcrypt. Pre-hash with SHA-256 is handled
            # in security.py for runtime; here we hash directly for seeding.
            password_hash = bcrypt.generate_password_hash(demo_password).decode('utf-8')

            conn.execute(
                'INSERT INTO users (email, password_hash) VALUES (?, ?)',
                (demo_email, password_hash),
            )
            conn.commit()

            print(f'  * Demo user created: {demo_email} / {demo_password}')

    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    """
    Look up a user by email address.

    Args:
        email: Normalized email address to look up.

    Returns:
        sqlite3.Row with user data, or None if not found.
        Uses parameterized query (?) to prevent SQL injection.
    """
    db = get_db()
    cursor = db.execute(
        'SELECT id, email, password_hash FROM users WHERE email = ?',
        (email,),
    )
    return cursor.fetchone()


# --- Login Attempts ---

def get_login_attempts(email: str) -> Optional[sqlite3.Row]:
    """Retrieve the login attempts record for an email."""
    db = get_db()
    cursor = db.execute(
        'SELECT * FROM login_attempts WHERE email = ?',
        (email,),
    )
    return cursor.fetchone()


def record_failed_attempt(email: str) -> dict:
    """
    Record a failed login attempt and return the current state.

    Increments the attempt counter and updates the timestamp.
    If the threshold is reached, sets the lockout timestamp with
    progressive duration.

    Returns:
        dict with keys: attempts, locked, remaining_attempts
    """
    db = get_db()
    now = time.time()  # Unix timestamp for lockout arithmetic
    threshold = current_app.config['LOCKOUT_THRESHOLD']  # Default: 5
    durations = current_app.config['LOCKOUT_DURATIONS']  # Progressive: [60s, 300s, 900s, 3600s]

    record = get_login_attempts(email)

    if record is None:
        # First failed attempt for this email.
        db.execute(
            'INSERT INTO login_attempts (email, attempts, last_attempt) VALUES (?, 1, ?)',
            (email, now),
        )
        db.commit()
        return {'attempts': 1, 'locked': False, 'remaining_attempts': threshold - 1}

    attempts = record['attempts'] + 1
    lockout_count = record['lockout_count']
    locked_until = None
    locked = False

    if attempts >= threshold:
        # Calculate progressive lockout duration.
        # Index into durations list, capping at the last (longest) duration.
        duration_index = min(lockout_count, len(durations) - 1)  # Cap at longest duration (1hr)
        duration = durations[duration_index]  # e.g., 1st lockout=60s, 2nd=300s, ...
        locked_until = now + duration  # Absolute unlock timestamp
        locked = True
        lockout_count += 1  # Escalate for next lockout
        attempts = 0  # Reset counter for next cycle after lockout expires

    db.execute(
        '''UPDATE login_attempts
           SET attempts = ?, locked_until = ?, lockout_count = ?, last_attempt = ?
           WHERE email = ?''',
        (attempts, locked_until, lockout_count, now, email),
    )
    db.commit()

    return {
        'attempts': attempts,
        'locked': locked,
        'remaining_attempts': max(0, threshold - attempts) if not locked else 0,
    }


def is_account_locked(email: str) -> bool:
    """
    Check if an account is currently locked out.

    Returns True if a lockout is active (locked_until > current time).
    Expired lockouts return False — the user can try again.
    """
    record = get_login_attempts(email)
    if record is None:
        return False

    locked_until = record['locked_until']
    if locked_until is None:
        return False

    return time.time() < locked_until  # True = still locked, False = lockout expired


def reset_login_attempts(email: str) -> None:
    """
    Reset login attempts after a successful login.

    Clears the attempt counter and lockout state.
    Preserves the record (doesn't delete) so lockout_count
    history is maintained for progressive lockout.
    """
    db = get_db()
    db.execute(
        '''UPDATE login_attempts
           SET attempts = 0, locked_until = NULL  -- Keep lockout_count for progressive escalation
           WHERE email = ?''',
        (email,),
    )
    db.commit()
