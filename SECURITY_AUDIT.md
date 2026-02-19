# Fluxer SSO / Session Handling — Security Audit

**Datum:** 19. Februar 2026  
**Scope:** `fluxer_sso/`, `fluxer_api/src/auth/`, `fluxer_api/src/middleware/`, `fluxer_api/src/sso/`

---

## Gesamtbewertung

**Die SSO- und Session-Architektur ist solide und folgt modernen Best Practices.**  
Keine kritischen Schwachstellen gefunden. Die nachfolgenden Punkte sind Härtungsmaßnahmen.

---

## Stärken

| Bereich                          | Umsetzung                                                                                          |
| -------------------------------- | --------------------------------------------------------------------------------------------------- |
| **Token-Signierung**             | RS256 (asymmetrisch) — API-Instanzen verifizieren JWTs lokal via Public Key, kein SSO-Round-Trip    |
| **PKCE**                         | Nur S256 erlaubt, kein Plain-Mode — schützt gegen Authorization Code Interception                   |
| **Auth-Code**                    | Einmalverwendung (sofort gelöscht nach Konsum), 5 Min TTL                                           |
| **Refresh Token Rotation**       | Alter Token wird bei jedem Refresh konsumiert, neuer ausgegeben — schützt bei Token-Leak            |
| **Session-Token-Speicherung**    | Nur SHA-256-Hash wird in DB gespeichert, nie das Token selbst                                       |
| **Cookie-Sicherheit**            | `httpOnly: true`, `secure: true` (Production), `sameSite: Lax` auf allen sicherheitsrelevanten Cookies |
| **Sudo-Mode**                    | HS256-JWT, 5 Min Lebensdauer, user-gebunden, Algorithm-Pinning verhindert Algorithm-Confusion       |
| **MFA**                          | TOTP, SMS, WebAuthn + Backup-Codes unterstützt                                                      |
| **Globale Session-Invalidierung**| Redis Pub/Sub notifiziert alle API-Instanzen bei Logout/Revocation                                  |
| **Rate Limiting**                | Per-Bucket + globale Limits auf allen Auth-Endpoints (Register, Login, MFA, Forgot Password)        |
| **Captcha**                      | hCaptcha / Cloudflare Turnstile auf Register, Login, Forgot Password                                |
| **JWKS / OpenID Discovery**      | Standard-Endpunkte (`/.well-known/jwks.json`, `/.well-known/openid-configuration`) vorhanden        |
| **Token Introspection**          | Prüft ob Session im globalen Store noch aktiv ist                                                   |
| **Revocation**                   | RFC 7009 konform (immer Success, auch wenn Token bereits ungültig)                                  |

---

## Findings

### 1. Service-Secret-Vergleich anfällig für Timing-Angriff

| | |
|---|---|
| **Schwere** | Mittel |
| **Datei** | `fluxer_sso/src/SsoRoutes.ts` — `verifyServiceAuth()` |
| **Problem** | String-Vergleich mit `===` statt `crypto.timingSafeEqual`. Ermöglicht theoretisch einen Timing-Seitenkanalangriff auf das Inter-Service-Secret. |

**Empfohlener Fix:**

```typescript
function verifyServiceAuth(authHeader: string | undefined): boolean {
    if (!authHeader) return false;
    const expected = `Service ${SsoConfig.serviceSecret}`;
    if (authHeader.length !== expected.length) return false;
    return crypto.timingSafeEqual(Buffer.from(authHeader), Buffer.from(expected));
}
```

---

### 2. SSO-Sync ist fire-and-forget (Eventually Consistent)

| | |
|---|---|
| **Schwere** | Mittel |
| **Datei** | `fluxer_api/src/auth/services/AuthSessionService.ts` |
| **Problem** | `syncSessionToSso()`, `invalidateSessionInSso()` und `invalidateAllUserSessionsInSso()` werden mit `void` aufgerufen (kein `await`). Bei SSO-Server-Ausfall bleibt die lokale Session gültig, und eine im SSO revozierte Session kann lokal weiterleben bis sie eigenständig abläuft. |

**Empfehlung:** Bewusste Design-Entscheidung (Verfügbarkeit > Konsistenz), sollte aber dokumentiert werden. Optional: Retry-Mechanismus mit exponential Backoff einbauen.

---

### 3. Wildcard-Redirect-URIs ermöglichen potenziell Open-Redirect

| | |
|---|---|
| **Schwere** | Mittel-Niedrig |
| **Datei** | `fluxer_sso/src/SsoRoutes.ts` — `isRedirectUriAllowed()` |
| **Problem** | Redirect-URI-Validierung erlaubt Wildcards (`endsWith('*')`). Zu breit konfigurierte Wildcards (z.B. `https://example.com/*`) könnten als Open-Redirect missbraucht werden. |

**Empfehlung:** Nur exakte Matches oder streng begrenzte Prefix-Matches erlauben. Wildcard-Feature dokumentieren und in Production die konfigurierte Liste auditieren.

---

### 4. Rate Limits im Testmodus deaktiviert

| | |
|---|---|
| **Schwere** | Mittel |
| **Datei** | `fluxer_api/src/middleware/RateLimitMiddleware.ts` |
| **Problem** | Wenn `testModeEnabled` aktiv ist, werden sämtliche Rate Limits übersprungen. Dieses Flag darf in Production nie aktiv sein. |

**Empfehlung:** CI/CD-Check einbauen, der sicherstellt, dass `testModeEnabled` in Production-Deployments immer `false` ist.

---

### 5. X-Forwarded-For wird direkt vertraut

| | |
|---|---|
| **Schwere** | Niedrig |
| **Datei** | `fluxer_api/src/sso/SsoSessionSync.ts` |
| **Problem** | Client-IP wird aus `X-Forwarded-For` extrahiert, ohne dass der Header auf Proxy-Ebene validiert wird. Sicherheit hängt vollständig von der korrekten Caddy-Konfiguration ab. |

**Empfehlung:** Sicherstellen, dass der Reverse Proxy (Caddy) `X-Forwarded-For` überschreibt und nicht an Client-gesetzte Werte anhängt.

---

### 6. Keine Token-Längenprüfung vor Hash-Berechnung

| | |
|---|---|
| **Schwere** | Niedrig |
| **Datei** | `fluxer_api/src/middleware/UserMiddleware.ts` |
| **Problem** | Tokens beliebiger Länge werden direkt gehasht und in der DB nachgeschlagen. Extrem lange Tokens verursachen unnötige Crypto- und DB-Arbeit. |

**Empfehlung:** Einfache Format-Validierung vor Hash-Berechnung (`flx_` Prefix + exakt 36 Zeichen):

```typescript
if (!token.startsWith('flx_') || token.length !== 40) return null;
```

---

## Zusammenfassung

| # | Finding                                    | Schwere       | Status       |
|---|--------------------------------------------|---------------|--------------|
| 1 | Timing-unsicherer Service-Secret-Vergleich | Mittel        | Offen        |
| 2 | Fire-and-forget SSO-Sync                   | Mittel        | Design-Entscheidung |
| 3 | Wildcard-Redirect-URIs                     | Mittel-Niedrig| Offen        |
| 4 | Rate Limits in Testmodus deaktiviert       | Mittel        | Prüfen       |
| 5 | X-Forwarded-For ohne Proxy-Validierung     | Niedrig       | Prüfen       |
| 6 | Keine Token-Längenprüfung                  | Niedrig       | Offen        |

**Priorität:** Finding #1 (Timing-Safe Comparison) ist ein Einzeiler-Fix und sollte zuerst umgesetzt werden.
