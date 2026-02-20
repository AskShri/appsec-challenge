# Static Security Analysis — Bandit Report

**Tool:** [Bandit](https://bandit.readthedocs.io/) v1.8.6 (Python security linter)
**Date:** 2026-02-20
**Scope:** `app/` (application code, 758 lines) and `tests/` (test code, 560 lines)

---

## Executive Summary

| Severity | Application Code | Test Code |
|----------|-----------------|-----------|
| **High** | 0 | 0 |
| **Medium** | 0 | 0 |
| **Low** | 1 | 79 |
| **Total** | **1** | **79** |

**Application code: clean.** Zero high or medium severity findings.

The single low-severity finding is an intentional design choice (demo user seed). The 79 test findings are all B101 (`assert` usage in pytest) — standard and expected.

---

## Application Code Findings

### B105: Hardcoded Password String — LOW / Accepted

```
Location: app/auth/models.py:91
Severity: Low   Confidence: Medium
CWE: CWE-259 (Use of Hard-coded Password)
```

```python
demo_email = 'demo@xero.com'
demo_password = 'SecureP@ss123!'    # ← Flagged
```

**Assessment: Accepted risk (intentional).**

This is the demo user seed for the challenge evaluation environment. The hardcoded password is:
- Only used in `init_db()` for initial database seeding
- Documented in SUBMISSION.md and printed to console on startup
- Required by the challenge specification for reviewer testing
- Not used in any authentication logic or production code path

**Production mitigation:** In production, user seeding would be handled by a migration script reading from environment variables or a secure vault, not hardcoded values. The `init_db()` seeding block would be removed entirely.

---

## Test Code Findings

### B101: Assert Used — LOW / Not Applicable (79 instances)

All 79 findings are `assert` statements in pytest test files. Bandit flags these because `assert` is stripped in optimized bytecode (`python -O`), which would be a concern in production code. However:

- These are **test files** — they are never compiled with optimization flags
- `assert` is the **standard pytest assertion mechanism**
- This is a known bandit false positive for test code

**Recommendation:** No action needed. If desired, these can be suppressed with `bandit -r tests/ --skip B101` or by adding `# nosec B101` annotations.

---

## Files Scanned

### Application Code (0 high/medium findings)

| File | Lines | Findings |
|------|-------|----------|
| `app/__init__.py` | 89 | 0 |
| `app/config.py` | 49 | 0 |
| `app/extensions.py` | 17 | 0 |
| `app/headers.py` | 67 | 0 |
| `app/logging_config.py` | 63 | 0 |
| `app/auth/__init__.py` | 10 | 0 |
| `app/auth/forms.py` | 37 | 0 |
| `app/auth/models.py` | 171 | 1 (Low — accepted) |
| `app/auth/routes.py` | 151 | 0 |
| `app/auth/security.py` | 104 | 0 |
| **Total** | **758** | **1** |

### Test Code (79 B101 — expected for pytest)

| File | Lines | Findings |
|------|-------|----------|
| `tests/conftest.py` | 76 | 0 |
| `tests/test_account_lockout.py` | 73 | 7 |
| `tests/test_auth.py` | 77 | 16 |
| `tests/test_csrf.py` | 60 | 8 |
| `tests/test_input_validation.py` | 34 | 5 |
| `tests/test_logout.py` | 30 | 6 |
| `tests/test_rate_limiting.py` | 41 | 8 |
| `tests/test_security_headers.py` | 100 | 15 |
| `tests/test_session_management.py` | 69 | 14 |
| **Total** | **560** | **79** (all B101) |

---

## What Bandit Verified Clean

The absence of findings confirms the application has no instances of:

| Check | What It Detects | Status |
|-------|----------------|--------|
| B301/B302 | Pickle/marshal deserialization (RCE risk) | Clean |
| B303 | Insecure hash functions (MD5, SHA1 for crypto) | Clean |
| B304/B305 | Insecure ciphers or cipher modes | Clean |
| B306 | Use of `mktemp` (race condition) | Clean |
| B307 | `eval()` usage (code injection) | Clean |
| B308 | `mark_safe` in Django templates | Clean |
| B310 | `urllib.urlopen` with user input | Clean |
| B311 | Random not suitable for crypto | Clean |
| B312-B315 | Insecure SSL/TLS configuration | Clean |
| B320 | XML parsing vulnerabilities (XXE) | Clean |
| B501-B504 | Requests without certificate verification | Clean |
| B506 | Unsafe YAML loading | Clean |
| B507 | SSH host key bypass | Clean |
| B601-B607 | Shell injection via `os.system`, `subprocess` | Clean |
| B608 | SQL injection via string formatting | Clean |
| B609 | Wildcard injection in shell commands | Clean |
| B610-B611 | Django SQL injection | Clean |
| B701-B703 | Jinja2 auto-escape disabled | Clean |

---

## Reproduction

```bash
# Application code (should show 1 Low finding)
bandit -r app/

# Application code, medium+ severity only (should show 0)
bandit -r app/ -ll

# Test code, excluding expected assert warnings
bandit -r tests/ --skip B101
```
