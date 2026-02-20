# Architecture Decision Register (ADR)

Each decision follows the format: **Context → Decision → Rationale → Trade-offs**.

---

## ADR-1: Language and Framework — Python/Flask

**Context:** Need to build a secure login system. Free choice of language/framework. Considered Django, Express.js (Node), Go net/http, and Flask.

**Decision:** Python 3.9+ with Flask 3.x.

**Rationale:**

- Familiarity — Python is my strongest language, so I could focus on security design rather than language mechanics
- Readable code — reviewers can assess security logic without language-specific expertise
- Rich security ecosystem: flask-limiter, flask-wtf, flask-bcrypt, flask-session
- Jinja2 auto-escaping prevents XSS by default
- Lightweight — minimal boilerplate, security logic is front and center

**Trade-offs:** Flask's simplicity means we implement some controls manually (e.g., security headers) rather than getting them from a batteries-included framework like Django. The trade-off is more code to own, but each control is explicit and auditable.

---

## ADR-2: Security Headers — Manual `@after_request`

**Context:** Need comprehensive HTTP security headers. Options: flask-talisman, secure, or manual implementation.

**Decision:** Manual `@after_request` handler in `app/headers.py`.

**Rationale:**

- flask-talisman is unmaintained (last release 2023, open security issues)
- Manual implementation shows understanding of each header's purpose
- Full control over nonce-based CSP without fighting library abstractions
- Easier to audit — all headers visible in one file

**Trade-offs:** More code to maintain, but for a login page the header set is well-defined and unlikely to change frequently.

---

## ADR-3: Session Storage — Server-Side Filesystem

**Context:** Flask's default sessions are client-side (signed cookies). Need to choose session strategy. Options: client-side (Flask default), server-side with Redis, server-side with filesystem, database-backed.

**Decision:** Server-side sessions via flask-session (filesystem backend).

**Rationale:**

- Client-side sessions leak data (email, login time visible in cookie even if signed)
- Server-side sessions mean the cookie contains only an opaque session ID
- Filesystem backend requires zero infrastructure (no Redis needed)
- Session data never leaves the server

**Trade-offs:** Filesystem sessions don't scale horizontally (sticky sessions needed). Production would use Redis. Acceptable for this scope — documented in SUBMISSION.md as production upgrade path.

---

## ADR-4: Password Hashing — bcrypt (12 rounds)

**Context:** Need to hash stored passwords. Options: bcrypt, Argon2, scrypt, PBKDF2.

**Decision:** bcrypt with cost factor 12 (~250ms per hash).

**Rationale:**

- OWASP-recommended (ASVS V2.4.1)
- 12 rounds balances security vs. UX latency (~250ms is imperceptible in login flow)
- Widely supported, well-audited implementation (py-bcrypt wraps OpenBSD bcrypt)
- Pre-hash with SHA-256 for passwords >72 bytes (bcrypt truncates at 72)

**Trade-offs:** Argon2id is the newer recommendation (memory-hard), but bcrypt is better supported in the Python ecosystem and sufficient for this context. NIST SP 800-63B accepts bcrypt.

---

## ADR-5: Data Persistence — SQLite

**Context:** Need to store users and login attempts. Options: PostgreSQL, MySQL, SQLite, in-memory dict.

**Decision:** SQLite via Python's built-in `sqlite3` module.

**Rationale:**

- Zero dependencies — included in Python stdlib
- Data persists across application restarts (unlike in-memory)
- Supports parameterized queries (SQL injection prevention)
- Clear upgrade path to PostgreSQL (same SQL patterns)

**Trade-offs:** SQLite has limited concurrent write throughput. Acceptable for a login portal; production would use PostgreSQL with connection pooling and Alembic migrations.

---

## ADR-6: Rate Limiting — Per-IP + Per-Account

**Context:** Need to defend against brute force and credential stuffing attacks. Options: per-IP only, per-account only, combined per-IP + per-account, CAPTCHA-based.

**Decision:** Dual rate limiting — 10/min per IP AND 5/min per account (email).

**Rationale:**

- Per-IP alone fails against distributed attacks (rotating IPs)
- Per-account alone fails against credential stuffing (rotating emails)
- Combined strategy defends against both attack patterns
- Generous limits (10/min IP) won't affect legitimate users

**Trade-offs:** In-memory storage (flask-limiter default) means limits reset on app restart. Production would use Redis for persistence.

---

## ADR-7: Error Messages — Generic Only

**Context:** Failed login could reveal whether an email exists in the system. Options: specific messages ("user not found" / "wrong password"), generic message, error codes.

**Decision:** Always return "Invalid email or password" regardless of failure reason.

**Rationale:**

- Per OWASP ASVS V2.2.1 and NIST SP 800-63B §5.1.1
- Prevents user enumeration attacks
- Combined with timing-safe verification, no information leaks through any channel

**Trade-offs:** Slightly worse UX for users who mistype their email — they won't know the email is wrong vs. the password. This is an accepted trade-off for a security-critical application.

---

## ADR-8: CSP Approach — Nonce-Based

**Context:** Need Content Security Policy to mitigate XSS. Options: nonce-based, hash-based, allowlist-based.

**Decision:** Per-request nonce generated via `secrets.token_urlsafe(32)`.

**Rationale:**

- Nonces are generated per-request — no stale hashes to maintain
- Works with dynamic content (no need to compute hashes at build time)
- `'strict-dynamic'` not needed (no script loading chains)
- 32-byte nonce provides 256 bits of entropy — unguessable

**Trade-offs:** Nonces require server-side rendering (templates must inject `nonce` attribute). This is natural with Jinja2.

---

## ADR-9: CSRF Protection — flask-wtf CSRFProtect

**Context:** Login form needs CSRF protection. Options: flask-wtf, manual token generation, SameSite-only.

**Decision:** flask-wtf CSRFProtect with `{{ form.hidden_tag() }}`.

**Rationale:**

- De facto Flask standard for CSRF
- Integrates with WTForms validation
- Generates and validates cryptographic tokens automatically
- SameSite=Lax provides an additional defense layer

**Trade-offs:** Adds a hidden field to the form. This is invisible to users and standard practice.

---

## ADR-10: Logout — POST-Only

**Context:** Logout endpoint method. Options: GET or POST.

**Decision:** POST-only with CSRF token.

**Rationale:**

- GET logout is vulnerable to CSRF (attacker embeds `<img src="/logout">`)
- POST with CSRF token prevents forced logout attacks
- Per OWASP ASVS V3.3.1

**Trade-offs:** Requires a form (button) rather than a simple link. Standard pattern for secure applications.

---

## ADR-11: Password Policy — NIST SP 800-63B Aligned

**Context:** Need to define password acceptance criteria. Options: traditional complexity rules (uppercase + number + symbol), length-only, NIST SP 800-63B aligned (length-based, no complexity).

**Decision:** Minimum 8 characters, maximum 128 characters. No complexity rules (no mandatory uppercase/numbers/symbols).

**Rationale:**

- NIST SP 800-63B §5.1.1 explicitly recommends AGAINST complexity rules
- Complexity rules lead to predictable patterns ("Password1!", "Summer2026!")
- Length-based policy encourages passphrases
- Maximum 128 chars prevents bcrypt-specific DoS (we pre-hash with SHA-256, but still bound the input)

**Trade-offs:** Users accustomed to complexity rules may perceive this as less secure. NIST research shows length-based policies produce stronger passwords in practice.