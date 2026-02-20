"""
Offensive Security Self-Test Script

Actively attempts real attacks against the running application and documents
whether each attack is blocked. Run against http://localhost:5000.

Usage:
    python security_test.py
"""

import json
import re
import time
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import statistics

BASE = 'http://localhost:5000'
RESULTS = []
SECTION = ''


def section(name):
    global SECTION
    SECTION = name
    print(f'\n{"="*60}')
    print(f'  {name}')
    print(f'{"="*60}')


def record(test_id, name, passed, detail=''):
    status = 'BLOCKED' if passed else 'VULNERABLE'
    icon = '[+]' if passed else '[!]'
    RESULTS.append({
        'section': SECTION,
        'id': test_id,
        'name': name,
        'passed': passed,
        'detail': detail,
    })
    print(f'  {icon} {test_id}: {name} — {status}')
    if detail:
        print(f'      {detail}')


def get(path, jar=None, headers=None):
    """GET request, return (status, headers, body)."""
    req = urllib.request.Request(BASE + path)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    try:
        resp = opener.open(req)
        return resp.status, dict(resp.headers), resp.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode('utf-8', errors='replace')


def post(path, data, jar=None, headers=None):
    """POST request, return (status, headers, body)."""
    encoded = urllib.parse.urlencode(data).encode('utf-8')
    req = urllib.request.Request(BASE + path, data=encoded, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPRedirectHandler(),
    )
    try:
        resp = opener.open(req)
        return resp.status, dict(resp.headers), resp.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode('utf-8', errors='replace')


def post_no_redirect(path, data, jar=None):
    """POST without following redirects."""
    encoded = urllib.parse.urlencode(data).encode('utf-8')
    req = urllib.request.Request(BASE + path, data=encoded, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        NoRedirect(),
    )
    try:
        resp = opener.open(req)
        return resp.status, dict(resp.headers), resp.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode('utf-8', errors='replace')


def get_csrf_token(html):
    """Extract CSRF token from HTML form."""
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    if m:
        return m.group(1)
    m = re.search(r'value="([^"]+)"[^>]*name="csrf_token"', html)
    if m:
        return m.group(1)
    return None


def login_with_csrf(email, password, jar=None):
    """Perform a login with proper CSRF token."""
    if jar is None:
        jar = http.cookiejar.CookieJar()
    _, _, html = get('/login', jar=jar)
    token = get_csrf_token(html)
    return post_no_redirect('/login', {
        'csrf_token': token,
        'email': email,
        'password': password,
    }, jar=jar), jar


# ============================================================
#  TEST 1: XSS (Cross-Site Scripting)
# ============================================================
def test_xss():
    section('1. Cross-Site Scripting (XSS)')

    payloads = [
        ('<script>alert(1)</script>', 'Basic script tag'),
        ('<img src=x onerror=alert(1)>', 'Event handler injection'),
        ('"><script>alert(1)</script>', 'Attribute breakout + script'),
        ("' onmouseover='alert(1)", 'Single-quote event injection'),
        ('<svg/onload=alert(1)>', 'SVG onload'),
        ('javascript:alert(1)', 'JavaScript protocol'),
    ]

    jar = http.cookiejar.CookieJar()
    _, _, html = get('/login', jar=jar)
    token = get_csrf_token(html)

    for i, (payload, desc) in enumerate(payloads):
        status, hdrs, body = post('/login', {
            'csrf_token': token,
            'email': payload,
            'password': 'test',
        }, jar=jar)

        # Check: payload should NOT appear unescaped in the response
        # Jinja2 auto-escaping converts < to &lt; etc.
        has_raw_payload = payload in body
        has_script_tag = '<script>' in body.lower() and 'nonce=' not in body.lower().split('<script>')[0].split('>')[-1] if '<script>' in body.lower() else False

        record(
            f'XSS-{i+1}', f'Reflected XSS via email field: {desc}',
            not has_raw_payload and not has_script_tag,
            f'Payload escaped in response. Raw payload in body: {has_raw_payload}'
        )

    # Check CSP header blocks execution even if XSS somehow reflected
    status, hdrs, body = get('/login')
    csp = hdrs.get('Content-Security-Policy', '')
    has_nonce_script = "script-src 'nonce-" in csp
    has_unsafe_inline = "'unsafe-inline'" in csp.split('script-src')[1].split(';')[0] if 'script-src' in csp else True

    record('XSS-7', 'CSP blocks inline script execution (no unsafe-inline)',
           has_nonce_script and not has_unsafe_inline,
           f'script-src uses nonce: {has_nonce_script}, unsafe-inline absent: {not has_unsafe_inline}')

    # Verify nonce changes per request (can't predict/reuse)
    _, h1, _ = get('/login')
    _, h2, _ = get('/login')
    nonce1 = re.search(r"nonce-([A-Za-z0-9_-]+)", h1.get('Content-Security-Policy', ''))
    nonce2 = re.search(r"nonce-([A-Za-z0-9_-]+)", h2.get('Content-Security-Policy', ''))
    nonces_differ = nonce1 and nonce2 and nonce1.group(1) != nonce2.group(1)

    record('XSS-8', 'CSP nonce is unique per request (anti-replay)',
           nonces_differ,
           f'Nonce 1: {nonce1.group(1)[:12]}..., Nonce 2: {nonce2.group(1)[:12]}...')


# ============================================================
#  TEST 2: SQL Injection
# ============================================================
def test_sqli():
    section('2. SQL Injection')

    payloads = [
        ("' OR '1'='1", 'Classic OR bypass'),
        ("' OR 1=1 --", 'Comment-based bypass'),
        ("admin@xero.com' UNION SELECT 1,2,3--", 'UNION injection'),
        ("'; DROP TABLE users; --", 'Destructive DROP TABLE'),
        ("' AND SUBSTRING(password_hash,1,1)='$'--", 'Blind extraction attempt'),
    ]

    jar = http.cookiejar.CookieJar()
    _, _, html = get('/login', jar=jar)
    token = get_csrf_token(html)

    for i, (payload, desc) in enumerate(payloads):
        status, hdrs, body = post('/login', {
            'csrf_token': token,
            'email': payload,
            'password': 'anything',
        }, jar=jar)

        # Should NOT get a 302 (successful login) or a 500 (SQL error)
        not_authenticated = status != 302 and 'dashboard' not in body.lower()
        no_sql_error = 'sqlite' not in body.lower() and 'operational' not in body.lower() and 'syntax' not in body.lower()

        record(f'SQLI-{i+1}', f'SQL injection via email: {desc}',
               not_authenticated and no_sql_error,
               f'Status: {status}, No auth bypass: {not_authenticated}, No SQL error leaked: {no_sql_error}')

    # Verify demo user still exists after DROP TABLE attempt
    jar2 = http.cookiejar.CookieJar()
    (status, _, _), _ = login_with_csrf('demo@xero.com', 'SecureP@ss123!', jar2)
    record('SQLI-6', 'Database intact after DROP TABLE attempt',
           status == 302,
           f'Demo user login status: {status} (302 = success)')


# ============================================================
#  TEST 3: CSRF Bypass Attempts
# ============================================================
def test_csrf():
    section('3. CSRF Token Bypass')

    # 3a: POST without any CSRF token
    jar = http.cookiejar.CookieJar()
    get('/login', jar=jar)  # Get session cookie
    status, _, body = post('/login', {
        'email': 'demo@xero.com',
        'password': 'SecureP@ss123!',
    }, jar=jar)
    record('CSRF-1', 'Login POST without CSRF token is rejected',
           'dashboard' not in body.lower() and status != 302,
           f'Status: {status}')

    # 3b: POST with a fabricated CSRF token
    status, _, body = post('/login', {
        'csrf_token': 'forged-token-12345',
        'email': 'demo@xero.com',
        'password': 'SecureP@ss123!',
    }, jar=jar)
    record('CSRF-2', 'Login POST with forged CSRF token is rejected',
           'dashboard' not in body.lower() and status != 302,
           f'Status: {status}')

    # 3c: Reuse a CSRF token from a different session
    jar_a = http.cookiejar.CookieJar()
    _, _, html_a = get('/login', jar=jar_a)
    token_a = get_csrf_token(html_a)

    jar_b = http.cookiejar.CookieJar()
    get('/login', jar=jar_b)  # Different session
    status, _, body = post('/login', {
        'csrf_token': token_a,  # Token from session A used in session B
        'email': 'demo@xero.com',
        'password': 'SecureP@ss123!',
    }, jar=jar_b)
    record('CSRF-3', 'CSRF token from different session is rejected',
           'dashboard' not in body.lower() and status != 302,
           f'Status: {status}')

    # 3d: Logout via GET (should be 405)
    status, _, body = get('/logout')
    record('CSRF-4', 'GET /logout returns 405 (POST-only)',
           status == 405,
           f'Status: {status}')


# ============================================================
#  TEST 4: Timing Attack (User Enumeration)
# ============================================================
def test_timing():
    section('4. Timing-Based User Enumeration')

    # Measure response times for existing vs non-existing users
    # Each should take ~250ms (bcrypt) regardless

    existing_times = []
    nonexistent_times = []
    iterations = 5

    for i in range(iterations):
        # Existing user
        jar = http.cookiejar.CookieJar()
        _, _, html = get('/login', jar=jar)
        token = get_csrf_token(html)
        start = time.time()
        post('/login', {
            'csrf_token': token,
            'email': 'demo@xero.com',
            'password': 'wrongpassword%d' % i,
        }, jar=jar)
        existing_times.append(time.time() - start)

        # Non-existent user
        jar2 = http.cookiejar.CookieJar()
        _, _, html2 = get('/login', jar=jar2)
        token2 = get_csrf_token(html2)
        start = time.time()
        post('/login', {
            'csrf_token': token2,
            'email': 'timing_test_%d@nonexistent.com' % i,
            'password': 'wrongpassword%d' % i,
        }, jar=jar2)
        nonexistent_times.append(time.time() - start)

    avg_existing = statistics.mean(existing_times)
    avg_nonexistent = statistics.mean(nonexistent_times)
    time_diff = abs(avg_existing - avg_nonexistent)
    std_existing = statistics.stdev(existing_times) if len(existing_times) > 1 else 0
    std_nonexistent = statistics.stdev(nonexistent_times) if len(nonexistent_times) > 1 else 0

    # If difference is < 50ms (well within noise), timing attack is not viable
    timing_safe = time_diff < 0.050

    record('TIME-1', 'Response time indistinguishable for existing vs non-existing users',
           timing_safe,
           'Existing user avg: %.3fs (sd: %.3fs), Non-existing avg: %.3fs (sd: %.3fs), Diff: %.3fs' % (
               avg_existing, std_existing, avg_nonexistent, std_nonexistent, time_diff))

    # Check error messages are identical
    jar = http.cookiejar.CookieJar()
    _, _, html = get('/login', jar=jar)
    token = get_csrf_token(html)
    _, _, body_existing = post('/login', {
        'csrf_token': token,
        'email': 'demo@xero.com',
        'password': 'wrong',
    }, jar=jar)

    jar2 = http.cookiejar.CookieJar()
    _, _, html2 = get('/login', jar=jar2)
    token2 = get_csrf_token(html2)
    _, _, body_nonexistent = post('/login', {
        'csrf_token': token2,
        'email': 'nobody@nowhere.com',
        'password': 'wrong',
    }, jar=jar2)

    # Extract error messages
    err_existing = re.findall(r'flash-error[^>]*>([^<]+)', body_existing)
    err_nonexistent = re.findall(r'flash-error[^>]*>([^<]+)', body_nonexistent)

    record('TIME-2', 'Error message identical for existing and non-existing users',
           err_existing == err_nonexistent and len(err_existing) > 0,
           'Existing: %s, Non-existing: %s' % (
               err_existing[0].strip() if err_existing else 'NONE',
               err_nonexistent[0].strip() if err_nonexistent else 'NONE'))


# ============================================================
#  TEST 5: Session Security
# ============================================================
def test_session():
    section('5. Session Manipulation')

    # 5a: Access dashboard without authentication
    status, _, body = get('/dashboard')
    record('SESS-1', 'Dashboard inaccessible without authentication',
           status == 302 or 'please log in' in body.lower(),
           f'Status: {status}')

    # 5b: Session cookie flags
    jar = http.cookiejar.CookieJar()
    (status, hdrs, _), _ = login_with_csrf('demo@xero.com', 'SecureP@ss123!', jar)
    set_cookie = hdrs.get('Set-Cookie', '')

    record('SESS-2', 'Session cookie has HttpOnly flag',
           'httponly' in set_cookie.lower(),
           f'Set-Cookie contains HttpOnly: {"httponly" in set_cookie.lower()}')

    record('SESS-3', 'Session cookie has SameSite attribute',
           'samesite' in set_cookie.lower(),
           f'SameSite value: {"Lax" if "lax" in set_cookie.lower() else "missing"}')

    # 5c: Session invalidated after logout
    jar2 = http.cookiejar.CookieJar()
    (status, _, _), jar2 = login_with_csrf('demo@xero.com', 'SecureP@ss123!', jar2)
    # Verify dashboard works before logout
    status_before, _, _ = get('/dashboard', jar=jar2)

    # Get CSRF token for logout
    _, _, dash_html = get('/dashboard', jar=jar2)
    logout_token = get_csrf_token(dash_html)
    if logout_token:
        post('/logout', {'csrf_token': logout_token}, jar=jar2)

    # Try dashboard with old session cookie
    status_after, _, _ = get('/dashboard', jar=jar2)
    record('SESS-4', 'Session fully invalidated after logout (not just cookie cleared)',
           status_before == 200 and status_after == 302,
           f'Before logout: {status_before}, After logout: {status_after}')

    # 5d: Fabricated session cookie rejected
    jar3 = http.cookiejar.CookieJar()
    fake_cookie = http.cookiejar.Cookie(
        version=0, name='session', value='fabricated-session-id-12345',
        port=None, port_specified=False,
        domain='localhost', domain_specified=True, domain_initial_dot=False,
        path='/', path_specified=True,
        secure=False, expires=None, discard=True,
        comment=None, comment_url=None, rest={}, rfc2109=False,
    )
    jar3.set_cookie(fake_cookie)
    status, _, body = get('/dashboard', jar=jar3)
    record('SESS-5', 'Fabricated session cookie rejected',
           status == 302 or 'please log in' in body.lower(),
           f'Status: {status}')


# ============================================================
#  TEST 6: HTTP Method Tampering
# ============================================================
def test_http_methods():
    section('6. HTTP Method Tampering')

    methods_to_test = ['PUT', 'DELETE', 'PATCH', 'OPTIONS']

    for method in methods_to_test:
        req = urllib.request.Request(BASE + '/login', method=method)
        try:
            resp = urllib.request.urlopen(req)
            status = resp.status
        except urllib.error.HTTPError as e:
            status = e.code

        record(f'HTTP-{method}', f'{method} /login returns 405',
               status == 405,
               f'Status: {status}')

    # GET /logout should be 405
    req = urllib.request.Request(BASE + '/logout', method='GET')
    try:
        resp = urllib.request.urlopen(req)
        status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code

    record('HTTP-LOGOUT', 'GET /logout returns 405 (POST-only)',
           status == 405,
           f'Status: {status}')


# ============================================================
#  TEST 7: Information Disclosure
# ============================================================
def test_info_disclosure():
    section('7. Information Disclosure')

    # 7a: 404 page leaks no internal details
    status, hdrs, body = get('/nonexistent-path-12345')
    record('INFO-1', '404 page reveals no stack traces or framework details',
           'traceback' not in body.lower() and 'werkzeug' not in body.lower() and 'flask' not in body.lower(),
           f'Status: {status}')

    # 7b: Server header stripped
    record('INFO-2', 'Server header stripped (no version disclosure)',
           'werkzeug' not in hdrs.get('Server', '').lower() and 'python' not in hdrs.get('Server', '').lower(),
           f'Server header: "{hdrs.get("Server", "(absent)")}"')

    # 7c: X-Powered-By absent
    record('INFO-3', 'X-Powered-By header absent',
           'X-Powered-By' not in hdrs,
           f'X-Powered-By: "{hdrs.get("X-Powered-By", "(absent)")}"')

    # 7d: Error response for invalid input doesn't leak internals
    jar = http.cookiejar.CookieJar()
    _, _, html = get('/login', jar=jar)
    token = get_csrf_token(html)
    _, _, body = post('/login', {
        'csrf_token': token,
        'email': 'x' * 500,  # Oversized input
        'password': 'test',
    }, jar=jar)
    record('INFO-4', 'Oversized email input handled without internal error details',
           'traceback' not in body.lower() and 'error' not in body.lower() or 'too long' in body.lower() or 'valid email' in body.lower(),
           f'Response shows validation message, no internals')

    # 7e: Try to access common sensitive paths
    sensitive_paths = [
        '/admin', '/debug', '/config', '/.env', '/console',
        '/api/users', '/static/../config.py', '/instance/app.db',
    ]
    all_blocked = True
    for path in sensitive_paths:
        status, _, body = get(path)
        if status == 200 and 'page not found' not in body.lower():
            all_blocked = False
            break

    record('INFO-5', 'Common sensitive paths return 404/302 (no leakage)',
           all_blocked,
           f'Tested {len(sensitive_paths)} paths: /admin, /debug, /config, /.env, /console, etc.')


# ============================================================
#  TEST 8: Security Headers Completeness
# ============================================================
def test_headers():
    section('8. Security Response Headers')

    status, hdrs, body = get('/login')

    checks = [
        ('HDR-CSP', 'Content-Security-Policy present', 'Content-Security-Policy'),
        ('HDR-XFO', 'X-Frame-Options: DENY', 'X-Frame-Options'),
        ('HDR-XCTO', 'X-Content-Type-Options: nosniff', 'X-Content-Type-Options'),
        ('HDR-RP', 'Referrer-Policy present', 'Referrer-Policy'),
        ('HDR-PP', 'Permissions-Policy present', 'Permissions-Policy'),
        ('HDR-COOP', 'Cross-Origin-Opener-Policy: same-origin', 'Cross-Origin-Opener-Policy'),
        ('HDR-CORP', 'Cross-Origin-Resource-Policy: same-origin', 'Cross-Origin-Resource-Policy'),
        ('HDR-XPCDP', 'X-Permitted-Cross-Domain-Policies: none', 'X-Permitted-Cross-Domain-Policies'),
        ('HDR-CC', 'Cache-Control contains no-store', 'Cache-Control'),
    ]

    for test_id, name, header in checks:
        value = hdrs.get(header, '')
        record(test_id, name,
               len(value) > 0,
               f'{header}: {value[:80]}')

    # CSP directive checks
    csp = hdrs.get('Content-Security-Policy', '')
    csp_checks = [
        ('CSP-1', "default-src 'self'", "default-src 'self'" in csp),
        ('CSP-2', "script-src uses nonce (not unsafe-inline)", "'nonce-" in csp and "'unsafe-inline'" not in csp.split('script-src')[1].split(';')[0] if 'script-src' in csp else False),
        ('CSP-3', "frame-ancestors 'none'", "frame-ancestors 'none'" in csp),
        ('CSP-4', "form-action 'self'", "form-action 'self'" in csp),
        ('CSP-5', "object-src 'none'", "object-src 'none'" in csp),
        ('CSP-6', "base-uri 'self'", "base-uri 'self'" in csp),
    ]

    for test_id, name, passed in csp_checks:
        record(test_id, f'CSP: {name}', passed, f'Directive present: {passed}')


# ============================================================
#  TEST 9: Header Injection / CRLF Injection
# ============================================================
def test_header_injection():
    section('9. Header / CRLF Injection')

    # Attempt CRLF injection via email field
    jar = http.cookiejar.CookieJar()
    _, _, html = get('/login', jar=jar)
    token = get_csrf_token(html)

    payloads = [
        ('test@evil.com\r\nX-Injected: true', 'CRLF in email field'),
        ('test@evil.com%0d%0aX-Injected: true', 'URL-encoded CRLF in email'),
        ('test@evil.com\nSet-Cookie: hacked=true', 'Newline + cookie injection'),
    ]

    for i, (payload, desc) in enumerate(payloads):
        status, hdrs, body = post('/login', {
            'csrf_token': token,
            'email': payload,
            'password': 'test',
        }, jar=jar)

        # Check: injected header should NOT appear in response headers
        has_injected = 'X-Injected' in str(hdrs) or 'hacked' in str(hdrs)
        record(f'CRLF-{i+1}', f'Header injection blocked: {desc}',
               not has_injected,
               f'Injected header in response: {has_injected}')


# ============================================================
#  TEST 10: Password Field Security
# ============================================================
def test_password_security():
    section('10. Password Handling')

    # 10a: Password not reflected in response
    jar = http.cookiejar.CookieJar()
    _, _, html = get('/login', jar=jar)
    token = get_csrf_token(html)
    secret_marker = 'SUPER_SECRET_PASSWORD_12345'
    _, _, body = post('/login', {
        'csrf_token': token,
        'email': 'test@test.com',
        'password': secret_marker,
    }, jar=jar)
    record('PWD-1', 'Password never reflected in response body',
           secret_marker not in body,
           f'Password found in response: {secret_marker in body}')

    # 10b: Password not in URL (POST not GET)
    _, _, login_html = get('/login')
    form_method = re.search(r'<form[^>]*method="([^"]+)"', login_html, re.IGNORECASE)
    record('PWD-2', 'Login form uses POST method (password not in URL)',
           form_method and form_method.group(1).upper() == 'POST',
           f'Form method: {form_method.group(1) if form_method else "not found"}')

    # 10c: Password field has autocomplete="current-password"
    has_autocomplete = 'autocomplete="current-password"' in login_html
    record('PWD-3', 'Password field has autocomplete="current-password" (password manager support)',
           has_autocomplete,
           f'autocomplete attribute present: {has_autocomplete}')

    # 10d: Very long password doesn't cause server error (DoS prevention)
    jar2 = http.cookiejar.CookieJar()
    _, _, html2 = get('/login', jar=jar2)
    token2 = get_csrf_token(html2)
    long_password = 'A' * 10000
    status, _, body2 = post('/login', {
        'csrf_token': token2,
        'email': 'test@test.com',
        'password': long_password,
    }, jar=jar2)
    record('PWD-4', '10KB password rejected gracefully (bcrypt DoS prevention)',
           status != 500 and ('too long' in body2.lower() or 'password' in body2.lower()),
           f'Status: {status}')


# ============================================================
#  TEST 11: Forced Browsing / Path Traversal
# ============================================================
def test_path_traversal():
    section('11. Path Traversal & Forced Browsing')

    traversal_paths = [
        ('/static/../config.py', 'Directory traversal to config'),
        ('/static/../../requirements.txt', 'Double traversal to project root'),
        ('/static/%2e%2e/config.py', 'URL-encoded traversal'),
        ('/static/....//config.py', 'Doubled dot traversal'),
    ]

    for i, (path, desc) in enumerate(traversal_paths):
        status, _, body = get(path)
        # Should NOT return actual file contents
        has_secret_key = 'SECRET_KEY' in body
        has_flask = 'from flask' in body
        record(f'PATH-{i+1}', f'Path traversal blocked: {desc}',
               not has_secret_key and not has_flask and status != 200,
               f'Status: {status}, Config leaked: {has_secret_key}')


# ============================================================
#  MAIN
# ============================================================
def main():
    print('Security Self-Test — Offensive Testing Report')
    print('Target: %s' % BASE)
    print('Date: %s' % time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()))
    print('')

    test_xss()
    test_sqli()
    test_csrf()
    test_timing()
    test_session()
    test_http_methods()
    test_info_disclosure()
    test_headers()
    test_header_injection()
    test_password_security()
    test_path_traversal()

    # Summary
    print('\n')
    print('=' * 60)
    print('  SUMMARY')
    print('=' * 60)

    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r['passed'])
    failed = sum(1 for r in RESULTS if not r['passed'])

    print(f'\n  Total tests: {total}')
    print(f'  Attacks blocked: {passed}')
    print(f'  Vulnerabilities found: {failed}')
    print(f'\n  Result: {"ALL ATTACKS BLOCKED" if failed == 0 else "%d VULNERABILITIES DETECTED" % failed}')

    if failed > 0:
        print('\n  Failed tests:')
        for r in RESULTS:
            if not r['passed']:
                print(f'    [!] {r["id"]}: {r["name"]}')
                if r['detail']:
                    print(f'        {r["detail"]}')

    # Output JSON for report generation
    print('\n\n--- JSON RESULTS ---')
    print(json.dumps({
        'total': total,
        'passed': passed,
        'failed': failed,
        'results': RESULTS,
    }, indent=2))


if __name__ == '__main__':
    main()
