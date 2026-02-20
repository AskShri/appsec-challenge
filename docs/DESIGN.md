# Technical Design Document — Secure Login Portal

**Author:** Security Engineering Lead
**Date:** 2026-02-20
**Status:** Approved

---

## 1. Architecture Overview

**Pattern:** Flask App Factory with single Blueprint
**Stack:** Python 3.9+ / Flask 3.x / SQLite / Server-side Sessions

```
┌─────────────────────────────────────────────────────┐
│                    Client (Browser)                   │
│  ┌─────────────────────────────────────────────────┐ │
│  │ CSP nonces │ SameSite cookies │ HSTS │ HttpOnly │ │
│  └─────────────────────────────────────────────────┘ │
└──────────────────────┬──────────────────────────────┘
                       │ HTTPS
┌──────────────────────▼──────────────────────────────┐
│                  Flask Application                    │
│                                                       │
│  ┌─── Outer Perimeter ───────────────────────────┐   │
│  │  Rate Limiter (flask-limiter)                  │   │
│  │  ├─ Per-IP: 10/min on POST /login             │   │
│  │  └─ Per-account: 5/min on POST /login         │   │
│  └───────────────────────────────────────────────┘   │
│                       │                               │
│  ┌─── Request Layer ─────────────────────────────┐   │
│  │  CSRF Validation (flask-wtf before_request)    │   │
│  │  Input Validation (WTForms)                    │   │
│  │  MAX_CONTENT_LENGTH (16KB)                     │   │
│  └───────────────────────────────────────────────┘   │
│                       │                               │
│  ┌─── Auth Layer ────────────────────────────────┐   │
│  │  Timing-Safe Credential Verification           │   │
│  │  ├─ bcrypt always runs (~250ms)               │   │
│  │  ├─ Dummy hash for non-existent users         │   │
│  │  └─ Constant-time regardless of outcome       │   │
│  │  Account Lockout Manager                       │   │
│  │  ├─ Progressive delays (1m→5m→15m→1h)        │   │
│  │  └─ Per-email tracking (all emails)           │   │
│  └───────────────────────────────────────────────┘   │
│                       │                               │
│  ┌─── Session Layer ─────────────────────────────┐   │
│  │  Server-Side Sessions (filesystem)             │   │
│  │  Session Regeneration on Login                 │   │
│  │  30-min Idle Timeout                           │   │
│  └───────────────────────────────────────────────┘   │
│                       │                               │
│  ┌─── Response Layer ────────────────────────────┐   │
│  │  Security Headers (after_request)              │   │
│  │  ├─ CSP (nonce-based)                         │   │
│  │  ├─ HSTS, X-Frame-Options, nosniff           │   │
│  │  ├─ Referrer-Policy, Permissions-Policy       │   │
│  │  ├─ Cache-Control: no-store                   │   │
│  │  └─ Server header stripped                    │   │
│  └───────────────────────────────────────────────┘   │
│                       │                               │
│  ┌─── Data Layer ────────────────────────────────┐   │
│  │  SQLite (parameterized queries only)           │   │
│  │  ├─ users(email, password_hash)               │   │
│  │  └─ login_attempts(email, attempts, locked)   │   │
│  └───────────────────────────────────────────────┘   │
│                                                       │
│  ┌─── Audit Layer ───────────────────────────────┐   │
│  │  JSON Structured Logging                       │   │
│  │  ├─ login_success, login_failed               │   │
│  │  ├─ account_locked, logout                    │   │
│  │  └─ csrf_failure, rate_limit_exceeded         │   │
│  └───────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
```

---

## 2. Request Lifecycle — Login POST

```
Client POST /login
    │
    ▼
[1] Rate Limiter Check ──── OVER LIMIT ──→ 429 Page
    │ (under limit)
    ▼
[2] CSRF Token Validation ── INVALID ────→ 400 + "Form expired" flash
    │ (valid)
    ▼
[3] WTForms Validation ──── INVALID ────→ Re-render with field errors
    │ (valid)
    ▼
[4] Timing-Safe Verify ── (bcrypt ALWAYS runs, ~250ms)
    │                      ├─ User exists: check real hash
    │                      └─ User absent: check dummy hash
    ▼
[5] Lockout Check ──────── LOCKED ──────→ Generic lockout message
    │ (not locked)
    ▼
[6] Credentials Valid? ─── NO ──────────→ Record failure, generic error
    │ (yes)                                (warn if ≤2 attempts remain)
    ▼
[7] Session Regeneration
    │
    ▼
[8] Set Session Data (email, login_time, IP)
    │
    ▼
[9] Reset Lockout Counter
    │
    ▼
[10] Audit Log: login_success
    │
    ▼
[11] Redirect → /dashboard (302)
    │
    ▼
[12] after_request: Security Headers Applied
```

**Critical Design Note:** Step [4] (bcrypt) MUST execute before Step [5] (lockout check). If we checked lockout first and returned early for locked accounts, an attacker could time responses to distinguish locked from unlocked accounts (~0ms vs ~250ms). By always running bcrypt, all responses take consistent time.

---

## 3. Component Responsibilities

| Component | File | Responsibility |
|-----------|------|----------------|
| App Factory | `app/__init__.py` | Creates and configures Flask app, registers extensions/blueprints |
| Config | `app/config.py` | All security thresholds and settings with justification comments |
| Headers | `app/headers.py` | Security response headers via `after_request` hook |
| Auth Blueprint | `app/auth/__init__.py` | Blueprint registration |
| Routes | `app/auth/routes.py` | HTTP handling: login, logout, dashboard views |
| Forms | `app/auth/forms.py` | Input validation via WTForms |
| Models | `app/auth/models.py` | SQLite database operations (users, login_attempts) |
| Security | `app/auth/security.py` | Lockout logic, timing-safe verification, audit helpers |
| Logging | `app/logging_config.py` | JSON structured audit logging |
| Extensions | `app/extensions.py` | Extension instances (limiter, csrf, bcrypt, session) |

---

## 4. Data Model

### users
```sql
CREATE TABLE users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### login_attempts
```sql
CREATE TABLE login_attempts (
    email         TEXT PRIMARY KEY,
    attempts      INTEGER NOT NULL DEFAULT 0,
    locked_until  REAL,            -- Unix timestamp
    lockout_count INTEGER NOT NULL DEFAULT 0,
    last_attempt  REAL             -- Unix timestamp
);
```

---

## 5. Session Data Structure

```python
session = {
    'user_email': 'demo@xero.com',      # Authenticated identity
    'login_time': '2026-02-20T10:30:00', # For display and audit
    'login_ip': '127.0.0.1',            # For session binding check
}
```

---

## 6. Security Control Integration Map

Shows how controls overlap to protect against each attack vector:

```
                    Brute   Session   XSS   CSRF   Clickjack   SQLi
                    Force   Hijack
Rate Limiting        ██
Account Lockout      ██
bcrypt Hashing       ██
Generic Errors       ██
Timing-Safe          ██
Dummy Hash           ██
HttpOnly Cookie             ██       ██
Secure Flag                 ██
SameSite=Lax                ██              ██
Server Sessions             ██
Session Regen               ██
CSP (nonces)                ██       ██
HSTS                        ██
X-Frame-Options                                     ██
frame-ancestors                                     ██
Jinja2 Escaping                      ██
nosniff                              ██
Input Validation     ██                                        ██
CSRF Tokens                                 ██
form-action 'self'                          ██
Parameterized SQL                                              ██
Email Validation                                               ██
```

Every attack vector has **3+ overlapping controls**.
