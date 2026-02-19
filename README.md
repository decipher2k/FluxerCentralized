> [!CAUTION]
> Holy smokes, what a ride. Fluxer is taking off much earlier than I'd expected.
>
> Over the past month, I've been working on a major refactor that touches every part of the codebase. The goal is to make Fluxer easier to develop, fully documented, and much simpler and lighter to self-host. This update also includes plenty of bug fixes and improvements, and it should help the Fluxer.app hosted deployment handle the current load far better.
>
> I know it's hard to resist, but please wait a little longer before you dive deep into the current codebase or try to set up self-hosting. I'm aware the current stack isn't very lightweight. In the next update, self-hosting should be straightforward, with a small set of services: Fluxer Server (TypeScript) using SQLite for persistence, Gateway (Erlang), and optionally LiveKit for voice and video.
>
> Self-hosted deployments won't include any traces of Plutonium, and nothing is paywalled. You can still configure your own tiers and limits in the admin panel.
>
> Thanks for bearing with me. Development on Fluxer is about to get much easier, and the project will be made sustainable through community contributions and bounties for development work. Stay tuned – there's not much left now.
>
> I thought I could take it a bit easier while shipping this stabilising update, but Discord's recent announcement has changed things.
>
> As soon as the refactor is live, I'll interact more actively and push updates to this repository more frequently. The remaining parts of the refactor are currently being worked on and are being tested by a small group of testers before I'm comfortable pushing everything publicly. After that, all work will happen openly in public.
>
> ❤️

<div align="left" style="margin:12px 0 8px;">
  <img src="./media/logo-graphic.png" alt="Fluxer graphic logo" width="360">
</div>

---

Fluxer is an open-source, independent instant messaging and VoIP platform. Built for friends, groups, and communities.

<div align="left" style="margin:16px 0 0; width:100%;">
  <img
    src="./media/app-showcase.png"
    alt="Fluxer app showcase"
    style="display:block; width:100%; max-width:1200px; box-sizing:border-box;"
  >
</div>

---

## Architecture

Fluxer is composed of several services, each responsible for a distinct part of the platform:

| Service | Language | Description |
|---|---|---|
| **fluxer_api** | TypeScript | Core REST API server |
| **fluxer_gateway** | Erlang | Real-time WebSocket gateway |
| **fluxer_sso** | TypeScript | Centralized SSO & session management server |
| **fluxer_app** | TypeScript | Desktop & web client (Electron + RSpack) |
| **fluxer_admin** | Gleam | Admin panel |
| **fluxer_media_proxy** | TypeScript | Media proxy & image processing |
| **fluxer_metrics** | Rust | Metrics collection service |
| **fluxer_marketing** | Gleam | Marketing site |
| **fluxer_docs** | TypeScript | Documentation site (Next.js) |

---

## SSO / Session Server (`fluxer_sso`)

The SSO server is a **centralized authentication and session management service** that provides single sign-on across all Fluxer instances. It acts as an **OAuth 2.0 / OpenID Connect-compatible authorization server** using the Authorization Code flow with PKCE (Proof Key for Code Exchange).

### Key Features

- **OAuth 2.0 + PKCE** — Secure browser-based authentication using the Authorization Code flow with S256 PKCE challenge method.
- **OpenID Connect Discovery** — Full `/.well-known/openid-configuration` and `/.well-known/jwks.json` endpoints for automatic client and service configuration.
- **Stateless Token Verification** — Access tokens are RS256-signed JWTs. API instances verify them locally using the public key from the JWKS endpoint — no round-trip to the SSO server needed.
- **Global Session Management** — Sessions are stored in Redis/Valkey and shared across all API instances. Supports listing all active sessions, selective invalidation, and global logout.
- **Refresh Token Rotation** — Single-use opaque refresh tokens with automatic rotation on each use, preventing replay attacks.
- **Pub/Sub Event Broadcasting** — Session lifecycle events (`session-created`, `session-invalidated`, `global-logout`) are published via Redis pub/sub so all API instances can react in real time (e.g., clear local caches, disconnect WebSockets).
- **Activity Tracking** — Session activity is tracked with configurable debouncing (default 5 min) to avoid write storms.
- **Cookie-based SSO Sessions** — A secure, HttpOnly, SameSite cookie (`__flx_sso_session`) enables silent re-authentication across Fluxer applications.
- **Token Introspection & Revocation** — Standard RFC 7662 introspection and RFC 7009 revocation endpoints for API instances.
- **Inter-service Authentication** — Service-to-service calls are authenticated via a shared secret (`Authorization: Service <secret>`).

### Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/.well-known/openid-configuration` | OpenID Connect discovery document |
| GET | `/.well-known/jwks.json` | JSON Web Key Set (public key for JWT verification) |
| GET | `/authorize` | OAuth 2.0 authorization (PKCE) |
| POST | `/token` | Token exchange (auth code → tokens) and refresh token rotation |
| GET | `/userinfo` | User identity claims (Bearer token) |
| POST | `/introspect` | Token introspection (RFC 7662) |
| POST | `/revoke` | Token revocation (RFC 7009) |
| POST | `/session/create` | Create a global SSO session |
| POST | `/session/validate` | Validate a session by token hash |
| GET | `/session/list/:userId` | List all active sessions for a user |
| POST | `/session/invalidate` | Invalidate specific sessions |
| POST | `/session/invalidate-all` | Global logout (all sessions for a user) |
| POST | `/session/set-cookie` | Set the SSO session cookie |
| POST | `/logout` | Clear SSO cookie and optionally invalidate sessions |
| GET | `/_health` | Health check |

### Getting Started

Generate the required RSA key pair and service secret:

```sh
cd fluxer_sso && pnpm generate-keys
```

This outputs an RSA-2048 key pair and a random service secret, ready to paste into your `.env` file.

### Configuration

All settings are configured via environment variables. Key options include:

| Variable | Default | Description |
|---|---|---|
| `SSO_PORT` | `8090` | Server listen port |
| `REDIS_URL` | — | Redis/Valkey connection URL |
| `SSO_JWT_PRIVATE_KEY` | — | RSA private key (PEM) for signing tokens |
| `SSO_JWT_PUBLIC_KEY` | — | RSA public key (PEM) for verification |
| `SSO_SERVICE_SECRET` | — | Shared secret for inter-service auth |
| `SSO_ACCESS_TOKEN_TTL` | `900` (15 min) | Access token lifetime in seconds |
| `SSO_REFRESH_TOKEN_TTL` | `2592000` (30 days) | Refresh token lifetime in seconds |
| `SSO_SESSION_TTL` | `2592000` (30 days) | Session TTL in seconds |
| `SSO_ACTIVITY_UPDATE_INTERVAL` | `300` (5 min) | Debounce interval for activity tracking |
| `SSO_ALLOWED_REDIRECT_URIS` | Auto-derived | Comma-separated allowed redirect URIs |
| `SSO_COOKIE_DOMAIN` | `""` | Domain for the SSO cookie |

See [`fluxer_sso/src/SsoConfig.ts`](fluxer_sso/src/SsoConfig.ts) for the full list of configuration options.

---

## Documentation

| Document | Description |
|----------|-------------|
| [LOCAL_SETUP.md](LOCAL_SETUP.md) | Local development & test environment setup with Docker Compose |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Code of Conduct |
| [SECURITY.md](SECURITY.md) | Security policy & vulnerability reporting |
| [SECURITY_AUDIT.md](SECURITY_AUDIT.md) | SSO / session handling security audit |
| [LICENSE.md](LICENSE.md) | License (AGPL-3.0) |

---

> [!NOTE]
> Docs are coming very soon! With your help and [donations](https://fluxer.app/donate), the self-hosting and documentation story will get a lot better.
