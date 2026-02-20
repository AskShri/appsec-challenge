"""
Tests for HTTP security response headers.

Verifies that every response includes the correct security headers
as specified in DESIGN.md §3 and headers.py.
"""


class TestContentSecurityPolicy:
    """Tests for CSP header."""

    def test_csp_present_on_response(self, client):
        """Every response must include a Content-Security-Policy header."""
        response = client.get('/login')
        assert 'Content-Security-Policy' in response.headers

    def test_csp_contains_nonce(self, client):
        """CSP must include a nonce directive for scripts and styles."""
        response = client.get('/login')
        csp = response.headers['Content-Security-Policy']
        assert "script-src 'nonce-" in csp
        assert "style-src 'self' 'nonce-" in csp

    def test_csp_nonce_changes_per_request(self, client):
        """Each request must get a unique CSP nonce (prevents reuse)."""
        response1 = client.get('/login')
        response2 = client.get('/login')

        csp1 = response1.headers['Content-Security-Policy']
        csp2 = response2.headers['Content-Security-Policy']

        # Extract nonces from the CSP header.
        import re
        nonces1 = re.findall(r"'nonce-([^']+)'", csp1)
        nonces2 = re.findall(r"'nonce-([^']+)'", csp2)

        assert nonces1, 'No nonce found in first response CSP'
        assert nonces2, 'No nonce found in second response CSP'
        assert nonces1[0] != nonces2[0], 'Nonces must be unique per request'

    def test_csp_frame_ancestors_none(self, client):
        """CSP must prevent framing (clickjacking protection)."""
        response = client.get('/login')
        csp = response.headers['Content-Security-Policy']
        assert "frame-ancestors 'none'" in csp

    def test_csp_form_action_self(self, client):
        """CSP must restrict form actions to same origin."""
        response = client.get('/login')
        csp = response.headers['Content-Security-Policy']
        assert "form-action 'self'" in csp

    def test_csp_object_src_none(self, client):
        """CSP must block plugin content (Flash, Java)."""
        response = client.get('/login')
        csp = response.headers['Content-Security-Policy']
        assert "object-src 'none'" in csp


class TestOtherSecurityHeaders:
    """Tests for non-CSP security headers."""

    def test_x_frame_options_deny(self, client):
        """X-Frame-Options must be DENY (legacy clickjacking protection)."""
        response = client.get('/login')
        assert response.headers.get('X-Frame-Options') == 'DENY'

    def test_x_content_type_options_nosniff(self, client):
        """X-Content-Type-Options must be nosniff (MIME confusion protection)."""
        response = client.get('/login')
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'

    def test_referrer_policy(self, client):
        """Referrer-Policy must limit URL leakage on cross-origin navigation."""
        response = client.get('/login')
        assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'

    def test_permissions_policy(self, client):
        """Permissions-Policy must disable unused browser features."""
        response = client.get('/login')
        pp = response.headers.get('Permissions-Policy', '')
        assert 'camera=()' in pp
        assert 'microphone=()' in pp

    def test_cross_origin_opener_policy(self, client):
        """COOP must be same-origin (Spectre mitigation)."""
        response = client.get('/login')
        assert response.headers.get('Cross-Origin-Opener-Policy') == 'same-origin'

    def test_cache_control_no_store(self, client):
        """Non-static responses must not be cached."""
        response = client.get('/login')
        cc = response.headers.get('Cache-Control', '')
        assert 'no-store' in cc

    def test_server_header_stripped(self, client):
        """Server header must be removed to prevent version disclosure."""
        response = client.get('/login')
        assert 'Server' not in response.headers

    def test_x_permitted_cross_domain_policies(self, client):
        """X-Permitted-Cross-Domain-Policies must be none."""
        response = client.get('/login')
        assert response.headers.get('X-Permitted-Cross-Domain-Policies') == 'none'
