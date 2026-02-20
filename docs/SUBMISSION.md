# Submission — Secure Login Portal

**Candidate:** Security Engineering Lead
**Date:** 2026-02-20
**Stack:** Python 3.9+ / Flask 3.x / SQLite / Server-side Sessions

---

## Executive Summary

I transformed the static HTML login form into a production-quality secure authentication system with **20+ overlapping security controls** across 6 attack vectors. The design prioritizes **defense-in-depth** — no single control is a single point of failure, and every attack vector has 3+ overlapping mitigations.

**Demo credentials:** `demo@xero.com` / `SecureP@ss123!`

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py

# Open http://localhost:5000
# Login with: demo@xero.com / SecureP@ss123!

# Run tests (55 tests)
pytest tests/ -v
```

---

## Architecture

```
Client → Rate Limiter → CSRF → Input Validation → Timing-Safe Auth → Lockout → Session → Security Headers → Response
```

```
appsec-challenge-1.1/
├── run.py                       # Entry point
├── app/
│   ├── __init__.py              # App factory
│   ├── config.py                # All security thresholds (documented)
│   ├── extensions.py            # Flask extensions
│   ├── headers.py               # Security response headers
│   ├── logging_config.py        # JSON structured audit logging
│   ├── auth/
│   │   ├── routes.py            # Login, logout, dashboard
│   │   ├── forms.py             # WTForms input validation
│   │   ├── models.py            # SQLite data access
│   │   └── security.py          # Timing-safe verification, audit
│   ├── templates/               # Jinja2 templates (CSP nonces)
│   └── static/styles.css        # Original CSS preserved + additions
├── tests/                       # 55 tests across 8 files
├── docs/                        # PRD, Design Doc, ADRs, Threat Model
├── index.html                   # Original (preserved)
└── styles.css                   # Original (preserved)
```

---

## Security Controls Implemented

| # | Control | Threat Mitigated | OWASP ASVS | Implementation |
|---|---------|-----------------|------------|----------------|
| 1 | bcrypt hashing (12 rounds) | Offline password cracking | V2.4.1 | `flask-bcrypt`, ~250ms/hash |
| 2 | Timing-safe verification | User enumeration via timing | V2.2.1 | Dummy hash for non-existent users |
| 3 | Generic error messages | User enumeration via response | V2.2.1 | Always "Invalid email or password" |
| 4 | Per-IP rate limiting (10/min) | Brute force from single source | V2.2.1 | `flask-limiter` on POST |
| 5 | Per-account rate limiting (5/min) | Distributed credential stuffing | V2.2.1 | Email-keyed rate limit |
| 6 | Progressive account lockout | Slow brute force | V2.2.1 | 1m→5m→15m→1h, auto-recovery |
| 7 | HttpOnly session cookies | XSS session theft | V3.4.1 | Flask config |
| 8 | SameSite=Lax cookies | CSRF, cross-origin leakage | V3.4.1 | Flask config |
| 9 | Server-side sessions | Session data exposure | V3.4.1 | `flask-session` filesystem |
| 10 | Session regeneration on login | Session fixation | V3.2.1 | `session.clear()` before re-populate |
| 11 | Server-side session invalidation | Incomplete logout | V3.3.1 | `session.clear()` on logout |
| 12 | POST-only logout | CSRF-based forced logout | V3.3.1 | Method routing |
| 13 | CSRF tokens | Cross-site request forgery | V4.2.2 | `flask-wtf` CSRFProtect |
| 14 | CSP (nonce-based) | XSS, data injection | V14.4.3 | Per-request 256-bit nonces |
| 15 | X-Frame-Options: DENY | Clickjacking (legacy browsers) | V14.4.7 | `after_request` header |
| 16 | CSP frame-ancestors: 'none' | Clickjacking (modern browsers) | V14.4.7 | CSP directive |
| 17 | HSTS | SSL stripping, MitM | V9.1.1 | `Strict-Transport-Security` header |
| 18 | X-Content-Type-Options: nosniff | MIME confusion attacks | V14.4.4 | `after_request` header |
| 19 | Referrer-Policy | URL path leakage | V14.4.5 | `strict-origin-when-cross-origin` |
| 20 | Parameterized SQL queries | SQL injection | V5.3.4 | `sqlite3` `?` placeholders |
| 21 | Input validation (WTForms) | Malformed input, injection | V5.1.1 | Server-side validation |
| 22 | MAX_CONTENT_LENGTH (16KB) | Request body DoS | V13.1.1 | Flask config |
| 23 | Audit logging (JSON) | Non-repudiation, monitoring | V7.1.1 | Structured security events |
| 24 | Server header stripping | Version fingerprinting | V14.4.1 | Strip Server, X-Powered-By |
| 25 | Permissions-Policy | Browser feature abuse | — | Disable camera, mic, geo, payment |
| 26 | Cache-Control: no-store | Cache-based data leakage | V14.4.6 | On all non-static responses |

---

## Defense-in-Depth Overlap Matrix

This matrix shows how controls overlap to protect against each attack. Every vector has **3+ layers**.

### Brute Force / Credential Stuffing — 6 Layers

| Layer | Control | What It Stops |
|-------|---------|---------------|
| 1 | Per-IP rate limiting (10/min) | Fast automated attacks from single source |
| 2 | Per-account rate limiting (5/min) | Distributed attacks rotating IPs against one email |
| 3 | Progressive account lockout | Slow-and-steady attacks under rate limits |
| 4 | bcrypt hashing (12 rounds, ~250ms) | Offline cracking if database breached |
| 5 | Generic error messages | Prevents confirming valid emails to focus attacks |
| 6 | Timing-safe verification (dummy hash) | Prevents timing-based enumeration to find targets |

Even if an attacker bypasses rate limiting (distributed botnet), they hit account lockout. Even if they find a lockout bypass, bcrypt makes each attempt slow. Even if they get the hash database, bcrypt makes cracking expensive.

### Session Hijacking — 7 Layers

| Layer | Control | What It Stops |
|-------|---------|---------------|
| 1 | HttpOnly cookies | XSS can't read session cookie |
| 2 | Secure flag (production) | Cookie never sent over HTTP |
| 3 | SameSite=Lax | Cookie not sent on cross-origin requests |
| 4 | Server-side session storage | Cookie contains only an opaque ID |
| 5 | Session regeneration on login | Prevents session fixation |
| 6 | CSP (nonce-based) | Blocks XSS that could exfiltrate via other means |
| 7 | HSTS | Forces HTTPS, prevents SSL-stripping MitM |

### Cross-Site Scripting (XSS) — 5 Layers

| Layer | Control | What It Stops |
|-------|---------|---------------|
| 1 | CSP with per-request nonces | Blocks unauthorized inline/external scripts |
| 2 | Jinja2 auto-escaping | Template-level output encoding |
| 3 | HttpOnly session cookies | Even if XSS executes, can't steal sessions |
| 4 | X-Content-Type-Options: nosniff | Prevents MIME-type confusion |
| 5 | Input validation (WTForms) | Rejects malformed input at the boundary |

### CSRF — 3 Layers

| Layer | Control | What It Stops |
|-------|---------|---------------|
| 1 | CSRF tokens (flask-wtf) | Cryptographic token validation |
| 2 | SameSite=Lax cookies | Browser-level cross-origin protection |
| 3 | CSP form-action 'self' | Prevents form action injection |

### SQL Injection — 3 Layers

| Layer | Control | What It Stops |
|-------|---------|---------------|
| 1 | Parameterized queries (? placeholders) | Prevents injection at database layer |
| 2 | Input validation (WTForms) | Rejects malformed input before query |
| 3 | Email format validation | Constrains input to valid email patterns |

---

## Key Design Decisions

| Decision | Choice | Why |
|----------|--------|-----|
| Language | Python/Flask | Readable, strong security ecosystem, reviewer-friendly |
| Security headers | Manual `@after_request` | Shows understanding; flask-talisman is unmaintained |
| Session storage | Server-side (filesystem) | Client-side sessions leak data |
| Password hashing | bcrypt (12 rounds) | OWASP recommended, ~250ms balance |
| Database | SQLite (stdlib) | Zero dependencies, data persists, clear PostgreSQL upgrade path |
| Error messages | Generic only | Prevents user enumeration (OWASP ASVS V2.2.1) |
| CSP | Nonce-based | Per-request entropy, no hash maintenance |
| Logout | POST-only | Prevents CSRF-based forced logout |
| Lockout | Progressive (1m→5m→15m→1h) | Balances security vs. accidental lockout UX |

Full rationale for each decision: `docs/DECISIONS.md` (11 ADRs with trade-off analysis).

---

## User Experience Considerations

Security controls are designed to be **invisible to legitimate users**:

| UX Feature | Security Constraint | How We Balance |
|------------|-------------------|----------------|
| Generic errors only | Can't tell user "wrong email" vs "wrong password" | Preserves email in form on failure (no re-typing) |
| Rate limits (10/min IP) | Must limit automated attacks | Generous enough that normal users never hit it |
| Account lockout | Must stop brute force | Progressive + auto-recovery (no admin needed) |
| Lockout warning | Must not reveal account existence | Warning appears for ALL emails (including non-existent) |
| CSRF tokens | Form must include token | Invisible to user (hidden field) |
| CSRF expiry | Token has limited lifetime | "Form session expired, please try again" — user just resubmits |
| CSP nonces | Must prevent XSS | Generated server-side, invisible to user |
| POST-only logout | Must prevent CSRF-forced logout | Styled as a button (natural UX pattern) |
| Autofocus on email | Reduces interaction friction | First field receives focus automatically |
| Password manager support | `autocomplete` attributes | `email` and `current-password` values set |

---

## Production Deployment

A hardened Docker deployment is included and ready to build:

```bash
# Generate secret key
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Build and run
docker-compose up -d

# Application available at http://localhost:5000
```

**Container hardening measures:**

| Measure | What It Prevents |
|---------|-----------------|
| Non-root user (`appuser`, UID 1000) | Privilege escalation if container is compromised |
| Read-only root filesystem | Malware persistence, webshell upload, config tampering |
| `cap_drop: ALL` | No Linux capabilities — can't mount, ptrace, or bind privileged ports |
| `no-new-privileges` | Prevents setuid/setgid escalation |
| tmpfs for writable dirs (`noexec`) | Written data can't be executed |
| Memory limit (256MB) | OOM-kill prevents resource exhaustion DoS |
| Log rotation (30MB max) | Prevents disk exhaustion via log flooding |
| gunicorn (not Werkzeug) | Production WSGI server — no debug endpoints, no reloader |
| Worker recycling (1000 req) | Mitigates memory leak accumulation |
| `server_software = ''` | No gunicorn version disclosure |
| Health check (30s interval) | Auto-restart on application failure |
| SECRET_KEY from env var | Never hardcoded — fails fast if missing |

Files: `Dockerfile`, `docker-compose.yml`, `gunicorn.conf.py`, `wsgi.py`, `.dockerignore`

---

## What Would Be Different in Production

| Area | Current | Production |
|------|---------|------------|
| Deployment | `python run.py` (Werkzeug) | Docker + gunicorn (included) |
| Session storage | Filesystem | Redis (distributed, TTL support, persistence) |
| Database | SQLite | PostgreSQL (connection pooling, Alembic migrations) |
| Rate limiting | In-memory | Redis-backed (survives restarts, distributed) |
| Authentication | Password only | MFA/2FA (TOTP via authenticator app, WebAuthn) |
| Password policy | Length-based | + HIBP Pwned Passwords API (k-anonymity check) |
| Infrastructure | Single instance | WAF (Web Application Firewall), load balancer, CDN |
| Anti-automation | Rate limit + lockout | + CAPTCHA (hCaptcha/Turnstile) after N failures |
| Monitoring | File-based audit log | Centralized logging (ELK/Splunk) with SIEM alerting |
| Cookie prefix | `session` | `__Host-session` (enforces Secure + no Domain) |
| TLS | Development HTTP | TLS 1.3, certificate pinning, HSTS preload |

---

## OWASP ASVS v4.0.3 Compliance Mapping

**58 applicable requirements mapped** across 8 ASVS chapters. Full mapping with gap analysis: [`docs/ASVS_MAPPING.md`](docs/ASVS_MAPPING.md).

| ASVS Chapter | Applicable | Implemented | Partial | Roadmap | Coverage |
|---|---|---|---|---|---|
| V2 — Authentication | 12 | 9 | 0 | 3 | 75% |
| V3 — Session Management | 12 | 9 | 2 | 1 | 75% |
| V4 — Access Control | 3 | 3 | 0 | 0 | 100% |
| V5 — Validation & Encoding | 7 | 7 | 0 | 0 | 100% |
| V7 — Error Handling & Logging | 8 | 8 | 0 | 0 | 100% |
| V8 — Data Protection | 4 | 4 | 0 | 0 | 100% |
| V13 — API & Web Service | 2 | 2 | 0 | 0 | 100% |
| V14 — Configuration | 10 | 10 | 0 | 0 | 100% |
| **Total** | **58** | **52** | **2** | **4** | **90%** |

**ASVS Level achieved: L1 (full) + L2 (partial).** Secondary mapping to NIST SP 800-63B included.

Key highlights from the mapping:
- **V2.2.1** (anti-automation): 3 independent layers — per-IP rate limiting, per-account rate limiting, progressive lockout
- **V3.2.1** (session regeneration): `session.clear()` before repopulating on login (fixation prevention)
- **V5.3.4** (injection prevention): parameterized queries exclusively — zero string concatenation
- **V7.3.1** (log protection): `sanitize_log_value()` strips control characters (CRLF injection prevention)
- **V14.4.3** (CSP): nonce-based with per-request 256-bit entropy, 8 directives

Acknowledged gaps documented in production roadmap: MFA (V2.8.1), breached password check (V2.1.7), absolute session timeout (V3.3.3), `__Host-` cookie prefix (V3.4.4).

---

## Test Suite

**55 tests** across 8 test files, all passing:

| Test File | Tests | What It Validates |
|-----------|-------|------------------|
| `test_auth.py` | 10 | Login success, failure, generic errors, redirects |
| `test_security_headers.py` | 14 | CSP, nonce uniqueness, frame protection, all headers |
| `test_session_management.py` | 8 | Cookie flags, regeneration, invalidation, login_required |
| `test_account_lockout.py` | 6 | Threshold, progressive delays, reset, non-existent email tracking |
| `test_rate_limiting.py` | 4 | IP limits, POST-only enforcement, headers |
| `test_csrf.py` | 4 | Token validation, token presence in forms |
| `test_input_validation.py` | 5 | Email/password validation, length limits |
| `test_logout.py` | 4 | Session clearing, redirect, POST-only, confirmation |

```bash
pytest tests/ -v  # All 55 tests pass
```

---

## Engineering Documentation

| Document | Purpose |
|----------|---------|
| `docs/PRD.md` | Product requirements, security requirements, success criteria |
| `docs/DESIGN.md` | Architecture, request lifecycle, data model, security control map |
| `docs/DECISIONS.md` | 11 Architecture Decision Records with trade-off analysis |
| `docs/THREAT_MODEL.md` | STRIDE analysis, risk matrix, residual risks |
| `docs/ASVS_MAPPING.md` | OWASP ASVS v4.0.3 compliance matrix (58 requirements) + NIST SP 800-63B |
| `docs/BANDIT_REPORT.md` | Static security analysis — zero high/medium findings (758 lines scanned) |
| `docs/SECURITY_TESTING.md` | Offensive security self-test — 61 attacks, 0 real vulnerabilities |

---

## AI Tools Disclosure

**Claude Code** (Anthropic) was used for code generation, security design review, and documentation. All code was reviewed, tested, and validated for correctness and security.

---

## References

- [OWASP ASVS v4.0](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) — Digital Identity Authentication Guidelines
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-307](https://cwe.mitre.org/data/definitions/307.html) — Improper Restriction of Excessive Authentication Attempts
- [CWE-384](https://cwe.mitre.org/data/definitions/384.html) — Session Fixation
- [CWE-614](https://cwe.mitre.org/data/definitions/614.html) — Sensitive Cookie Without HttpOnly Flag
