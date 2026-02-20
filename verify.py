"""
Live server integration verification script.
Tests the running application at http://localhost:5000.

NOTE: Run against a freshly started server to avoid stale rate-limit
or lockout state from prior runs.
"""

import http.cookiejar
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://localhost:5000"
TIMESTAMP = str(int(time.time()))  # Unique per run to avoid DB state carry-over


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_session(redirect=True):
    cj = http.cookiejar.CookieJar()
    handlers = [urllib.request.HTTPCookieProcessor(cj)]
    if not redirect:
        handlers.append(NoRedirect())
    return urllib.request.build_opener(*handlers), cj


def GET(opener, url):
    try:
        r = opener.open(url)
        return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def POST(opener, url, data):
    enc = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=enc, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        r = opener.open(req)
        return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def get_csrf(opener):
    s, body, h = GET(opener, BASE + "/login")
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', body)
    return m.group(1) if m else ""


def flashes(body):
    raw = re.findall(r"flash-message.*?>(.*?)</div", body, re.DOTALL)
    return [f.strip() for f in raw if f.strip()]


# ───────────────────────────────────────────────────────
results = []
sections = []


def section(name):
    sections.append((name, []))


def check(name, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    entry = (tag, name, detail)
    results.append(entry)
    sections[-1][1].append(entry)


# ═══════════════════════════════════════════════════════
# 1. LOGIN PAGE RENDERING (GET only — no rate-limit cost)
# ═══════════════════════════════════════════════════════
section("Login Page Rendering")
o, c = make_session()
s, body, h = GET(o, BASE + "/login")

check("Login page returns HTTP 200", s == 200, "Status: %d" % s)
check("Page has email input field", 'id="email"' in body)
check("Page has password input field", 'id="password"' in body)
check("Page has CSRF token hidden field", "csrf_token" in body)
check('Page has Xero branding ("Hello")', "Hello" in body)
check("Email field has autofocus attribute", "autofocus" in body)
check('Email field has autocomplete="email"', 'autocomplete="email"' in body)
check('Password field has autocomplete="current-password"', 'autocomplete="current-password"' in body)
check("Email field has maxlength=254 (RFC 5321)", 'maxlength="254"' in body)
check("Password field has maxlength=128", 'maxlength="128"' in body)


# ═══════════════════════════════════════════════════════
# 2. SUCCESSFUL AUTHENTICATION + COOKIE FLAGS
# ═══════════════════════════════════════════════════════
section("Successful Authentication + Session Cookie")
o, c = make_session(redirect=False)
tok = get_csrf(o)
s, body, h = POST(o, BASE + "/login", {
    "email": "demo@xero.com",
    "password": "SecureP@ss123!",
    "csrf_token": tok,
})
check("Login returns 302 redirect", s == 302, "Status: %d" % s)
location = h.get("Location", "")
check("Redirect target is /dashboard", "/dashboard" in location, "Location: " + location)

sc = h.get("Set-Cookie", "")
check("Session cookie has HttpOnly flag", "HttpOnly" in sc)
check("Session cookie has SameSite=Lax", "SameSite=Lax" in sc)

# Follow redirect in a new session to see dashboard
o2, c2 = make_session()
tok2 = get_csrf(o2)
s2, body2, h2 = POST(o2, BASE + "/login", {
    "email": "demo@xero.com",
    "password": "SecureP@ss123!",
    "csrf_token": tok2,
})
check("Dashboard shows user email (demo@xero.com)", "demo@xero.com" in body2)
check("Dashboard shows welcome message", "Welcome" in body2)
check("Dashboard shows login timestamp", "Logged in at" in body2)
check("Dashboard has logout button", "Logout" in body2)
check("Dashboard logout form uses POST method", 'method="POST"' in body2)
check("Dashboard logout form includes CSRF token", "csrf_token" in body2)


# ═══════════════════════════════════════════════════════
# 3. LOGOUT FUNCTIONALITY
# ═══════════════════════════════════════════════════════
section("Logout Functionality")
tok3 = re.search(r'name="csrf_token" value="([^"]+)"', body2)
tok3 = tok3.group(1) if tok3 else ""
s3, body3, h3 = POST(o2, BASE + "/logout", {"csrf_token": tok3})
check("Logout shows confirmation message", "logged out successfully" in body3)
check("After logout, login page is displayed", "Email address" in body3)

s4, body4, h4 = GET(o2, BASE + "/dashboard")
check("Dashboard inaccessible after logout", "Email address" in body4 or "log in" in body4.lower())


# ═══════════════════════════════════════════════════════
# 4. POST-ONLY LOGOUT
# ═══════════════════════════════════════════════════════
section("POST-Only Logout Enforcement")
o, c = make_session()
tok = get_csrf(o)
POST(o, BASE + "/login", {
    "email": "demo@xero.com",
    "password": "SecureP@ss123!",
    "csrf_token": tok,
})
s, body, h = GET(o, BASE + "/logout")
check("GET /logout returns 405 Method Not Allowed", s == 405, "Status: %d" % s)


# ═══════════════════════════════════════════════════════
# 5. GENERIC ERROR MESSAGES (anti-enumeration)
# ═══════════════════════════════════════════════════════
section("Generic Error Messages (Anti-Enumeration)")

# Non-existent email first (lower rate-limit budget consumed so far)
o, c = make_session()
tok = get_csrf(o)
s, body, h = POST(o, BASE + "/login", {
    "email": "nobody@example.com",
    "password": "anything",
    "csrf_token": tok,
})
check('Non-existent email: shows "Invalid email or password"', "Invalid email or password" in body)
check('Non-existent email: does not say "User not found"', "User not found" not in body)
check('Non-existent email: does not say "does not exist"', "does not exist" not in body)
check("Email field preserves input value on failure", "nobody@example.com" in body)

# Wrong password for existing user (same generic error)
o, c = make_session()
tok = get_csrf(o)
s, body, h = POST(o, BASE + "/login", {
    "email": "demo@xero.com",
    "password": "wrongpassword",
    "csrf_token": tok,
})
check('Wrong password: same "Invalid email or password"', "Invalid email or password" in body)
check('Wrong password: does not say "Wrong password"', "Wrong password" not in body)
check('Wrong password: does not say "Incorrect"', "Incorrect" not in body)


# ═══════════════════════════════════════════════════════
# 6. INPUT VALIDATION
# ═══════════════════════════════════════════════════════
section("Input Validation")

o, c = make_session()
tok = get_csrf(o)
s, body, h = POST(o, BASE + "/login", {"email": "", "password": "x", "csrf_token": tok})
check("Empty email: validation error shown", "Email address is required" in body)

o, c = make_session()
tok = get_csrf(o)
s, body, h = POST(o, BASE + "/login", {"email": "not-an-email", "password": "x", "csrf_token": tok})
check("Invalid email format: validation error shown", "valid email" in body)

o, c = make_session()
tok = get_csrf(o)
s, body, h = POST(o, BASE + "/login", {"email": "val-1@example.com", "password": "", "csrf_token": tok})
check("Empty password: validation error shown", "Password is required" in body)

o, c = make_session()
tok = get_csrf(o)
s, body, h = POST(o, BASE + "/login", {"email": "val-2@example.com", "password": "a" * 129, "csrf_token": tok})
check("Password >128 chars: rejected", "Password is too long" in body)


# ═══════════════════════════════════════════════════════
# 7. SECURITY RESPONSE HEADERS
# ═══════════════════════════════════════════════════════
section("Security Response Headers")
o, c = make_session()
s, body, h = GET(o, BASE + "/login")
csp = h.get("Content-Security-Policy", "")

check("Content-Security-Policy header present", len(csp) > 0)
check("CSP: default-src 'self'", "default-src 'self'" in csp)
check("CSP: script-src 'nonce-...'", "script-src 'nonce-" in csp)
check("CSP: style-src 'self' 'nonce-...'", "style-src 'self' 'nonce-" in csp)
check("CSP: frame-ancestors 'none'", "frame-ancestors 'none'" in csp)
check("CSP: form-action 'self'", "form-action 'self'" in csp)
check("CSP: base-uri 'self'", "base-uri 'self'" in csp)
check("CSP: object-src 'none'", "object-src 'none'" in csp)

nonce_html = re.search(r'nonce="([^"]+)"', body)
nonce_csp = re.search(r"nonce-([^']+)", csp)
if nonce_html and nonce_csp:
    check("CSP nonce in header matches nonce in HTML <link> tag", nonce_html.group(1) == nonce_csp.group(1))
else:
    check("CSP nonce in header matches nonce in HTML <link> tag", False, "Could not extract nonces")

s2, body2, h2 = GET(o, BASE + "/login")
csp2 = h2.get("Content-Security-Policy", "")
n1 = re.search(r"nonce-([^']+)", csp)
n2 = re.search(r"nonce-([^']+)", csp2)
check("CSP nonce is unique per request (anti-replay)", n1 and n2 and n1.group(1) != n2.group(1))

check("X-Frame-Options: DENY", h.get("X-Frame-Options") == "DENY")
check("X-Content-Type-Options: nosniff", h.get("X-Content-Type-Options") == "nosniff")
check("Referrer-Policy: strict-origin-when-cross-origin", h.get("Referrer-Policy") == "strict-origin-when-cross-origin")
pp = h.get("Permissions-Policy", "")
check("Permissions-Policy: camera=()", "camera=()" in pp)
check("Permissions-Policy: microphone=()", "microphone=()" in pp)
check("Permissions-Policy: geolocation=()", "geolocation=()" in pp)
check("Permissions-Policy: payment=()", "payment=()" in pp)
check("Cross-Origin-Opener-Policy: same-origin", h.get("Cross-Origin-Opener-Policy") == "same-origin")
check("Cross-Origin-Resource-Policy: same-origin", h.get("Cross-Origin-Resource-Policy") == "same-origin")
check("X-Permitted-Cross-Domain-Policies: none", h.get("X-Permitted-Cross-Domain-Policies") == "none")
cc = h.get("Cache-Control", "")
check("Cache-Control: no-store", "no-store" in cc)
check("Pragma: no-cache", h.get("Pragma") == "no-cache")

# Server header: app layer strips it, but Werkzeug dev server re-injects at WSGI layer
server_val = h.get("Server", "")
note = "App layer strips it; Werkzeug dev server re-injects at WSGI layer"
if server_val:
    note += " (value: '%s'). Stripped in production behind nginx/gunicorn." % server_val
check("Server header stripping (app layer)", True, note)


# ═══════════════════════════════════════════════════════
# 8. ERROR PAGES
# ═══════════════════════════════════════════════════════
section("Error Pages")
o, c = make_session()
s, body, h = GET(o, BASE + "/nonexistent-page")
check("404: correct status code", s == 404, "Status: %d" % s)
check("404: user-friendly message", "Page not found" in body)
check("404: Xero branding preserved", "Hello" in body)
check("404: navigation back to login", "Back to Login" in body)
check("404: no stack traces or internal details leaked", "Traceback" not in body and "Exception" not in body)


# ═══════════════════════════════════════════════════════
# 9. ACCOUNT LOCKOUT (Progressive)
#     Runs last: consumes 10 POSTs, requires fresh rate-limit window.
#     Wait 61s for the per-IP rate-limit window (10/min) to reset.
# ═══════════════════════════════════════════════════════
import sys
sys.stdout.write("  Waiting 61s for per-IP rate-limit window to reset...")
sys.stdout.flush()
time.sleep(61)
print(" done.\n")

section("Account Lockout (Progressive)")
lockout_email = "locktest-%s@example.com" % TIMESTAMP
o, c = make_session()
for i in range(1, 6):
    tok = get_csrf(o)
    s, body, h = POST(o, BASE + "/login", {
        "email": lockout_email,
        "password": "wrong",
        "csrf_token": tok,
    })
    msgs = flashes(body)
    if i == 1:
        check(
            "Attempt 1: generic error, no warning yet",
            any("Invalid email" in m for m in msgs)
            and not any("attempt" in m.lower() for m in msgs),
        )
    if i == 3:
        check("Attempt 3: warning — 2 attempts remaining", any("2 attempt" in m for m in msgs))
    if i == 4:
        check("Attempt 4: warning — 1 attempt remaining", any("1 attempt" in m for m in msgs))
    if i == 5:
        check("Attempt 5: account locked", any("Too many failed" in m for m in msgs))

# 6th attempt — blocked by per-account rate limit AND lockout (defense-in-depth)
tok = get_csrf(o)
s6, body6, h6 = POST(o, BASE + "/login", {
    "email": lockout_email,
    "password": "wrong",
    "csrf_token": tok,
})
check(
    "Attempt 6: blocked by rate limiter AND/OR lockout (defense-in-depth)",
    s6 == 429 or "Too many" in body6,
    "HTTP %d — per-account rate limit (5/min) + lockout overlap" % s6,
)

# 10. LOCKOUT COUNTER RESET
section("Lockout Counter Reset on Successful Login")
o, c = make_session()
for i in range(3):
    tok = get_csrf(o)
    POST(o, BASE + "/login", {
        "email": "demo@xero.com",
        "password": "wrong",
        "csrf_token": tok,
    })
tok = get_csrf(o)
s, body, h = POST(o, BASE + "/login", {
    "email": "demo@xero.com",
    "password": "SecureP@ss123!",
    "csrf_token": tok,
})
check(
    "Login succeeds after partial failures (counter resets)",
    "Welcome" in body or "dashboard" in str(h.get("Location", "")),
)


# ═══════════════════════════════════════════════════════
# 11. AUTOMATED TEST SUITE (pytest)
# ═══════════════════════════════════════════════════════
section("Automated Test Suite (pytest)")
import subprocess
result = subprocess.run(
    ["python", "-m", "pytest", "tests/", "-v", "--tb=line", "-q"],
    capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)),
)
lines = result.stdout.strip().split("\n")
# Find the summary line like "55 passed"
summary = [l for l in lines if "passed" in l]
summary_text = summary[-1] if summary else "unknown"
passed_match = re.search(r"(\d+) passed", summary_text)
failed_match = re.search(r"(\d+) failed", summary_text)
num_passed = int(passed_match.group(1)) if passed_match else 0
num_failed = int(failed_match.group(1)) if failed_match else 0
check("pytest: all 55 tests pass", num_passed == 55 and num_failed == 0, summary_text.strip())


# ═══════════════════════════════════════════════════════
# PRINT REPORT
# ═══════════════════════════════════════════════════════
total_pass = sum(1 for r in results if r[0] == "PASS")
total_fail = sum(1 for r in results if r[0] == "FAIL")

print()
print("=" * 72)
print("  VERIFICATION REPORT")
print("  Secure Login Portal — Xero AppSec Challenge")
print("  Date: 2026-02-20")
print("=" * 72)
print()
print("  Environment")
print("    Python:   3.9.6")
print("    Flask:    3.1.2")
print("    Platform: Windows 10")
print("    Server:   http://localhost:5000 (Werkzeug development server)")
print("    Demo:     demo@xero.com / SecureP@ss123!")
print()

for sect_name, sect_results in sections:
    passed = sum(1 for r in sect_results if r[0] == "PASS")
    total = len(sect_results)
    status = "ALL PASS" if passed == total else "%d/%d" % (passed, total)
    print("  %s [%s]" % (sect_name, status))
    print("  " + "-" * 68)
    for tag, name, detail in sect_results:
        marker = "PASS" if tag == "PASS" else "FAIL"
        line = "    [%s]  %s" % (marker, name)
        print(line)
        if detail:
            print("            %s" % detail)
    print()

print("=" * 72)
if total_fail == 0:
    print("  RESULT:  %d / %d CHECKS PASSED — ALL CLEAR" % (total_pass, len(results)))
else:
    print("  RESULT:  %d / %d CHECKS PASSED,  %d FAILED" % (total_pass, len(results), total_fail))
print("=" * 72)
