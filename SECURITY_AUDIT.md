# Fluxer SSO / Session Handling — Security Audit

**Date:** February 19, 2026  
**Scope:** `fluxer_sso/`, `fluxer_api/src/auth/`, `fluxer_api/src/middleware/`, `fluxer_api/src/sso/`

---

## Overall Assessment

**The SSO and session architecture is solid and follows modern best practices.**  
No critical vulnerabilities found. The findings below are hardening recommendations.

---

## Strengths

| Area                             | Implementation                                                                                      |
| -------------------------------- | --------------------------------------------------------------------------------------------------- |
| **Token Signing**                | RS256 (asymmetric) — API instances verify JWTs locally via public key, no SSO round-trip required    |
| **PKCE**                         | Only S256 allowed, no plain mode — protects against authorization code interception                  |
| **Auth Code**                    | Single-use (deleted immediately after consumption), 5 min TTL                                       |
| **Refresh Token Rotation**       | Old token is consumed on each refresh, new one issued — protects against token leaks                 |
| **Session Token Storage**        | Only SHA-256 hash is stored in DB, never the token itself                                           |
| **Cookie Security**              | `httpOnly: true`, `secure: true` (production), `sameSite: Lax` on all security-relevant cookies     |
| **Sudo Mode**                    | HS256 JWT, 5 min lifetime, user-bound, algorithm pinning prevents algorithm confusion                |
| **MFA**                          | TOTP, SMS, WebAuthn + backup codes supported                                                        |
| **Global Session Invalidation**  | Redis Pub/Sub notifies all API instances on logout/revocation                                       |
| **Rate Limiting**                | Per-bucket + global limits on all auth endpoints (register, login, MFA, forgot password)             |
| **Captcha**                      | hCaptcha / Cloudflare Turnstile on register, login, forgot password                                 |
| **Account Lockout**              | Escalating lockout per email: 5 failures → 15 min, 10 → 1 h, 20 → 24 h — mitigates distributed brute-force |
| **JWKS / OpenID Discovery**      | Standard endpoints (`/.well-known/jwks.json`, `/.well-known/openid-configuration`) present          |
| **Token Introspection**          | Verifies whether the session is still active in the global store                                    |
| **Revocation**                   | RFC 7009 compliant (always returns success, even if the token is already invalid)                    |

---

## Findings

### 1. Service Secret Comparison Vulnerable to Timing Attack

| | |
|---|---|
| **Severity** | Medium |
| **File** | `fluxer_sso/src/SsoRoutes.ts` — `verifyServiceAuth()` |
| **Issue** | String comparison uses `===` instead of `crypto.timingSafeEqual`. This theoretically enables a timing side-channel attack on the inter-service secret. |

**Recommended Fix:**

```typescript
function verifyServiceAuth(authHeader: string | undefined): boolean {
    if (!authHeader) return false;
    const expected = `Service ${SsoConfig.serviceSecret}`;
    if (authHeader.length !== expected.length) return false;
    return crypto.timingSafeEqual(Buffer.from(authHeader), Buffer.from(expected));
}
```

---

### 2. SSO Sync is Fire-and-Forget (Eventually Consistent)

| | |
|---|---|
| **Severity** | Medium |
| **File** | `fluxer_api/src/auth/services/AuthSessionService.ts` |
| **Issue** | `syncSessionToSso()`, `invalidateSessionInSso()`, and `invalidateAllUserSessionsInSso()` are called with `void` (no `await`). If the SSO server is down, the local session remains valid, and a session revoked in SSO can continue to work locally until it expires independently. |

**Recommendation:** This is a deliberate design decision (availability > consistency), but it should be documented. Optionally, implement a retry mechanism with exponential backoff.

---

### 3. Wildcard Redirect URIs May Enable Open Redirect

| | |
|---|---|
| **Severity** | Medium-Low |
| **File** | `fluxer_sso/src/SsoRoutes.ts` — `isRedirectUriAllowed()` |
| **Issue** | Redirect URI validation allows wildcards (`endsWith('*')`). Overly broad wildcards (e.g., `https://example.com/*`) could be exploited as an open redirect. |

**Recommendation:** Allow only exact matches or strictly bounded prefix matches. Document the wildcard feature and audit the configured list in production.

---

### 4. Rate Limits Disabled in Test Mode

| | |
|---|---|
| **Severity** | Medium |
| **File** | `fluxer_api/src/middleware/RateLimitMiddleware.ts` |
| **Issue** | When `testModeEnabled` is active, all rate limits are bypassed. This flag must never be active in production. |

**Recommendation:** Add a CI/CD check to ensure `testModeEnabled` is always `false` in production deployments.

---

### 5. X-Forwarded-For Trusted Directly

| | |
|---|---|
| **Severity** | Low |
| **File** | `fluxer_api/src/sso/SsoSessionSync.ts` |
| **Issue** | Client IP is extracted from `X-Forwarded-For` without proxy-level validation. Security depends entirely on correct Caddy configuration. |

**Recommendation:** Ensure the reverse proxy (Caddy) overwrites `X-Forwarded-For` rather than appending to client-set values.

---

### 6. No Token Length Validation Before Hashing

| | |
|---|---|
| **Severity** | Low |
| **File** | `fluxer_api/src/middleware/UserMiddleware.ts` |
| **Issue** | Tokens of arbitrary length are hashed directly and looked up in the DB. Extremely long tokens cause unnecessary crypto and DB work. |

**Recommendation:** Add simple format validation before hashing (`flx_` prefix + exactly 36 characters):

```typescript
if (!token.startsWith('flx_') || token.length !== 40) return null;
```

---

## Summary

| # | Finding                                    | Severity      | Status              |
|---|--------------------------------------------|---------------|---------------------|
| 1 | Timing-unsafe service secret comparison    | Medium        | Open                |
| 2 | Fire-and-forget SSO sync                   | Medium        | Design decision     |
| 3 | Wildcard redirect URIs                     | Medium-Low    | Open                |
| 4 | Rate limits disabled in test mode          | Medium        | Needs verification  |
| 5 | X-Forwarded-For without proxy validation   | Low           | Needs verification  |
| 6 | No token length validation                 | Low           | Open                |

**Priority:** Finding #1 (timing-safe comparison) is a one-liner fix and should be addressed first.
