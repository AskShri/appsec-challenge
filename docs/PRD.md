# Product Requirements Document — Secure Login Portal

**Author:** Security Engineering Lead
**Date:** 2026-02-20
**Status:** Approved
**Version:** 1.0

---

## 1. Problem Statement

Xero is launching a new internal portal. The existing login form (`index.html`) is a static HTML/CSS page with no backend, no authentication logic, and no security controls. Before deployment, this form must be enhanced into a production-quality secure authentication system that defends against common authentication-based attacks while maintaining a clean user experience.

As a financial SaaS company, Xero handles sensitive business data. A compromised internal portal could provide lateral movement opportunities for attackers. Authentication security is therefore critical — not just for user protection, but for regulatory compliance (SOC 2, data protection obligations).

---

## 2. Goals

1. **Protect user credentials** against brute force, credential stuffing, and enumeration attacks
2. **Secure session lifecycle** from creation through logout
3. **Harden HTTP responses** against XSS, clickjacking, and injection attacks
4. **Maintain usability** — security controls should be invisible to legitimate users
5. **Demonstrate defense-in-depth** — no single control is a single point of failure

---

## 3. Security Requirements

Derived from OWASP Application Security Verification Standard (ASVS) v4.0 and NIST SP 800-63B:

| ID | Requirement | OWASP ASVS | Priority |
|----|-------------|------------|----------|
| SR-1 | Passwords must be hashed with bcrypt (cost ≥ 10) | V2.4.1 | P0 |
| SR-2 | Authentication errors must not reveal whether email exists | V2.2.1 | P0 |
| SR-3 | Rate limiting on login endpoint | V2.2.1 | P0 |
| SR-4 | Account lockout after repeated failures | V2.2.1 | P0 |
| SR-5 | Session cookies: HttpOnly, Secure, SameSite | V3.4.1 | P0 |
| SR-6 | Session regeneration on authentication | V3.2.1 | P0 |
| SR-7 | Server-side session invalidation on logout | V3.3.1 | P0 |
| SR-8 | CSRF protection on state-changing requests | V4.2.2 | P0 |
| SR-9 | Content Security Policy header | V14.4.3 | P0 |
| SR-10 | Clickjacking protection headers | V14.4.7 | P0 |
| SR-11 | Timing-safe credential verification | V2.2.1 | P1 |
| SR-12 | Audit logging of security events | V7.1.1 | P1 |

---

## 4. Functional Requirements

### 4.1 Login
- User submits email + password via HTML form
- System authenticates against stored credentials
- On success: create session, redirect to dashboard
- On failure: display generic error, record failed attempt

### 4.2 Dashboard
- Displays welcome message with user identity
- Confirms active session
- Provides logout action

### 4.3 Logout
- POST-only endpoint (CSRF protection)
- Clears server-side session
- Deletes session cookie
- Redirects to login with confirmation message

---

## 5. Non-Functional Requirements

| Requirement | Target |
|-------------|--------|
| Login response time | < 500ms (dominated by bcrypt ~250ms) |
| Rate limit tolerance | 10 requests/minute per IP (legitimate users won't hit this) |
| Lockout recovery | Progressive: 1m → 5m → 15m → 1h (self-service, no admin needed) |
| Session timeout | 30 minutes idle |
| Browser support | Modern browsers (CSP Level 2+) |

---

## 6. Out of Scope (Future Work)

These are documented as intentional decisions, not oversights:

- **User registration** — Portal uses pre-provisioned accounts
- **Password reset** — Requires email infrastructure
- **Multi-factor authentication** — Recommended for production (TOTP, WebAuthn)
- **HIBP password checking** — Requires external API integration
- **Remember me** — Increases session hijacking window
- **OAuth/SAML** — Enterprise SSO integration would be production requirement
- **CAPTCHA** — Would add after progressive lockout proves insufficient

---

## 7. Success Criteria

1. All security controls from Section 3 are implemented and tested
2. No security control creates a single point of failure
3. Legitimate users experience zero friction under normal use
4. Test suite validates all security behaviors
5. Code is clean, well-documented, and maintainable
