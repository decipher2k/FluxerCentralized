/*
 * Copyright (C) 2026 Fluxer Contributors
 *
 * This file is part of Fluxer.
 *
 * Fluxer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Fluxer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Fluxer. If not, see <https://www.gnu.org/licenses/>.
 */

import crypto from 'node:crypto';
import {Hono} from 'hono';
import {getCookie, setCookie, deleteCookie} from 'hono/cookie';
import {SsoConfig} from './SsoConfig.js';
import type {GlobalSessionStore} from './GlobalSessionStore.js';
import type {SsoTokenService} from './SsoTokenService.js';
import {Logger} from './Logger.js';

const SSO_SESSION_COOKIE = '__flx_sso_session';

/**
 * Verify the PKCE code_verifier against the stored code_challenge.
 * SHA-256 of verifier, base64url-encoded, should match the challenge.
 */
function verifyPkceChallenge(codeVerifier: string, codeChallenge: string): boolean {
	const hash = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
	return hash === codeChallenge;
}

function generateAuthCode(): string {
	return crypto.randomBytes(32).toString('base64url');
}

function generateRefreshToken(): string {
	return crypto.randomBytes(48).toString('base64url');
}

/**
 * Validate that a redirect URI is allowed.
 */
function isRedirectUriAllowed(uri: string): boolean {
	return SsoConfig.allowedRedirectUris.some((allowed) => {
		if (allowed.endsWith('*')) {
			return uri.startsWith(allowed.slice(0, -1));
		}
		return uri === allowed;
	});
}

/**
 * Verify inter-service auth (API → SSO).
 */
function verifyServiceAuth(authHeader: string | undefined): boolean {
	if (!authHeader) return false;
	const expected = `Service ${SsoConfig.serviceSecret}`;
	return authHeader === expected;
}

export function createSsoRoutes(
	sessionStore: GlobalSessionStore,
	tokenService: SsoTokenService,
) {
	const app = new Hono();

	// ─── Health Check ────────────────────────────────────────────────

	app.get('/_health', (ctx) => ctx.text('OK'));

	// ─── JWKS Endpoint ──────────────────────────────────────────────
	// API instances fetch this to verify SSO JWTs locally without
	// contacting the SSO server on every request.

	app.get('/.well-known/jwks.json', async (ctx) => {
		const jwk = await tokenService.exportPublicKeyJwk();
		return ctx.json({
			keys: [{...jwk, alg: 'RS256', use: 'sig', kid: 'fluxer-sso-1'}],
		});
	});

	// ─── OpenID Discovery ───────────────────────────────────────────

	app.get('/.well-known/openid-configuration', (ctx) => {
		const baseUrl = SsoConfig.endpoints.sso;
		return ctx.json({
			issuer: SsoConfig.jwt.issuer,
			authorization_endpoint: `${baseUrl}/authorize`,
			token_endpoint: `${baseUrl}/token`,
			userinfo_endpoint: `${baseUrl}/userinfo`,
			jwks_uri: `${baseUrl}/.well-known/jwks.json`,
			end_session_endpoint: `${baseUrl}/logout`,
			introspection_endpoint: `${baseUrl}/introspect`,
			revocation_endpoint: `${baseUrl}/revoke`,
			response_types_supported: ['code'],
			grant_types_supported: ['authorization_code', 'refresh_token'],
			code_challenge_methods_supported: ['S256'],
			token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
			scopes_supported: ['identify', 'email', 'guilds', 'guilds.join'],
			subject_types_supported: ['public'],
			id_token_signing_alg_values_supported: ['RS256'],
		});
	});

	// ─── Authorize Endpoint (PKCE) ──────────────────────────────────
	// Step 1: Client redirects user here with PKCE challenge.
	// If user has an SSO session cookie, issue auth code immediately.
	// Otherwise, return a login form / redirect to login.

	app.get('/authorize', async (ctx) => {
		const {
			response_type,
			client_id,
			redirect_uri,
			code_challenge,
			code_challenge_method,
			scope,
			state,
		} = ctx.req.query();

		// Validate required params
		if (response_type !== 'code') {
			return ctx.json({error: 'unsupported_response_type'}, 400);
		}
		if (!client_id || !redirect_uri || !code_challenge || !state) {
			return ctx.json({error: 'invalid_request', error_description: 'Missing required parameters'}, 400);
		}
		if (code_challenge_method && code_challenge_method !== 'S256') {
			return ctx.json({error: 'invalid_request', error_description: 'Only S256 is supported'}, 400);
		}
		if (!isRedirectUriAllowed(redirect_uri)) {
			return ctx.json({error: 'invalid_request', error_description: 'Redirect URI not allowed'}, 400);
		}

		// Store PKCE challenge
		await sessionStore.storePkceChallenge(state, {
			codeChallenge: code_challenge,
			codeChallengeMethod: 'S256',
			clientId: client_id,
			redirectUri: redirect_uri,
			scope: scope || 'identify',
		});

		// Check for existing SSO session
		const sessionId = getCookie(ctx, SSO_SESSION_COOKIE);
		if (sessionId) {
			const session = await sessionStore.getSession(sessionId);
			if (session) {
				// User already has a valid global session — issue auth code
				const authCode = generateAuthCode();

				await sessionStore.storeAuthorizationCode({
					code: authCode,
					userId: session.userId,
					sessionId: session.sessionId,
					redirectUri: redirect_uri,
					codeChallenge: code_challenge,
					codeChallengeMethod: 'S256',
					clientId: client_id,
					scope: scope || 'identify',
					createdAt: new Date().toISOString(),
					expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
				});

				// Redirect back with auth code
				const redirectUrl = new URL(redirect_uri);
				redirectUrl.searchParams.set('code', authCode);
				redirectUrl.searchParams.set('state', state);
				return ctx.redirect(redirectUrl.toString());
			}
		}

		// No valid session — return login_required so the client shows a login form
		// or redirects to the SSO login page
		return ctx.json({
			error: 'login_required',
			login_url: `${SsoConfig.endpoints.sso}/login?state=${encodeURIComponent(state)}`,
			state,
		}, 401);
	});

	// ─── Login Endpoint ─────────────────────────────────────────────
	// Inter-service call: the API instance authenticates the user locally
	// and then calls this endpoint to create a global SSO session.
	// Only accessible with the service secret.

	app.post('/session/create', async (ctx) => {
		if (!verifyServiceAuth(ctx.req.header('Authorization'))) {
			return ctx.json({error: 'unauthorized'}, 401);
		}

		const body = await ctx.req.json<{
			userId: string;
			tokenHash: string;
			clientIp: string;
			userAgent: string | null;
			isDesktop: boolean;
			originInstance: string;
			state?: string;
		}>();

		// Create global session
		const session = await sessionStore.createSession({
			userId: body.userId,
			tokenHash: body.tokenHash,
			clientIp: body.clientIp,
			userAgent: body.userAgent,
			isDesktop: body.isDesktop,
			originInstance: body.originInstance,
		});

		// If a PKCE state was provided, issue an auth code
		let authCode: string | undefined;
		if (body.state) {
			const pkce = await sessionStore.consumePkceChallenge(body.state);
			if (pkce) {
				authCode = generateAuthCode();
				await sessionStore.storeAuthorizationCode({
					code: authCode,
					userId: body.userId,
					sessionId: session.sessionId,
					redirectUri: pkce.redirectUri,
					codeChallenge: pkce.codeChallenge,
					codeChallengeMethod: 'S256',
					clientId: pkce.clientId,
					scope: pkce.scope,
					createdAt: new Date().toISOString(),
					expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
				});
			}
		}

		return ctx.json({
			session_id: session.sessionId,
			user_id: session.userId,
			created_at: session.createdAt,
			auth_code: authCode,
		});
	});

	// ─── Token Endpoint ─────────────────────────────────────────────
	// Step 2: Exchange auth code + PKCE verifier for access + refresh tokens.

	app.post('/token', async (ctx) => {
		const body = await ctx.req.parseBody();
		const grantType = body.grant_type as string;

		if (grantType === 'authorization_code') {
			const code = body.code as string;
			const codeVerifier = body.code_verifier as string;
			const redirectUri = body.redirect_uri as string;

			if (!code || !codeVerifier || !redirectUri) {
				return ctx.json({error: 'invalid_request'}, 400);
			}

			// Consume the auth code
			const authCode = await sessionStore.consumeAuthorizationCode(code);
			if (!authCode) {
				return ctx.json({error: 'invalid_grant', error_description: 'Authorization code expired or already used'}, 400);
			}

			// Verify redirect URI matches
			if (authCode.redirectUri !== redirectUri) {
				return ctx.json({error: 'invalid_grant', error_description: 'Redirect URI mismatch'}, 400);
			}

			// Verify PKCE
			if (!verifyPkceChallenge(codeVerifier, authCode.codeChallenge)) {
				return ctx.json({error: 'invalid_grant', error_description: 'PKCE verification failed'}, 400);
			}

			// Verify session still exists
			const session = await sessionStore.getSession(authCode.sessionId);
			if (!session) {
				return ctx.json({error: 'invalid_grant', error_description: 'Session no longer valid'}, 400);
			}

			// Issue tokens
			const accessToken = await tokenService.issueAccessToken({
				userId: authCode.userId,
				sessionId: authCode.sessionId,
				scope: authCode.scope,
			});

			const refreshTokenStr = generateRefreshToken();
			await sessionStore.storeRefreshToken({
				refreshToken: refreshTokenStr,
				sessionId: authCode.sessionId,
				userId: authCode.userId,
				ttl: SsoConfig.jwt.refreshTokenTtl,
			});

			return ctx.json({
				access_token: accessToken,
				token_type: 'Bearer',
				expires_in: SsoConfig.jwt.accessTokenTtl,
				refresh_token: refreshTokenStr,
				scope: authCode.scope,
				session_id: authCode.sessionId,
			});
		}

		if (grantType === 'refresh_token') {
			const refreshToken = body.refresh_token as string;
			if (!refreshToken) {
				return ctx.json({error: 'invalid_request'}, 400);
			}

			// Consume the old refresh token
			const tokenData = await sessionStore.consumeRefreshToken(refreshToken);
			if (!tokenData) {
				return ctx.json({error: 'invalid_grant', error_description: 'Refresh token expired or already used'}, 400);
			}

			// Verify session still exists
			const session = await sessionStore.getSession(tokenData.sessionId);
			if (!session) {
				return ctx.json({error: 'invalid_grant', error_description: 'Session no longer valid'}, 400);
			}

			// Issue new tokens (token rotation)
			const accessToken = await tokenService.issueAccessToken({
				userId: tokenData.userId,
				sessionId: tokenData.sessionId,
			});

			const newRefreshToken = generateRefreshToken();
			await sessionStore.storeRefreshToken({
				refreshToken: newRefreshToken,
				sessionId: tokenData.sessionId,
				userId: tokenData.userId,
				ttl: SsoConfig.jwt.refreshTokenTtl,
			});

			return ctx.json({
				access_token: accessToken,
				token_type: 'Bearer',
				expires_in: SsoConfig.jwt.accessTokenTtl,
				refresh_token: newRefreshToken,
			});
		}

		return ctx.json({error: 'unsupported_grant_type'}, 400);
	});

	// ─── Userinfo Endpoint ──────────────────────────────────────────
	// Returns basic identity info for the authenticated user.

	app.get('/userinfo', async (ctx) => {
		const authHeader = ctx.req.header('Authorization');
		if (!authHeader?.startsWith('Bearer ')) {
			return ctx.json({error: 'unauthorized'}, 401);
		}

		const token = authHeader.slice('Bearer '.length);
		const payload = await tokenService.verifyAccessToken(token);
		if (!payload) {
			return ctx.json({error: 'invalid_token'}, 401);
		}

		return ctx.json({
			sub: payload.sub,
			session_id: payload.sid,
			scope: payload.scope,
			iss: payload.iss,
		});
	});

	// ─── Token Introspection ────────────────────────────────────────
	// API instances call this to validate tokens and check session state.
	// Service-to-service authenticated.

	app.post('/introspect', async (ctx) => {
		if (!verifyServiceAuth(ctx.req.header('Authorization'))) {
			return ctx.json({error: 'unauthorized'}, 401);
		}

		const body = await ctx.req.parseBody();
		const token = body.token as string;

		if (!token) {
			return ctx.json({active: false});
		}

		const payload = await tokenService.verifyAccessToken(token);
		if (!payload) {
			return ctx.json({active: false});
		}

		// Verify session still active in global store
		const session = await sessionStore.getSession(payload.sid);
		if (!session) {
			return ctx.json({active: false});
		}

		return ctx.json({
			active: true,
			sub: payload.sub,
			sid: payload.sid,
			scope: payload.scope,
			iss: payload.iss,
			exp: payload.exp,
			iat: payload.iat,
			client_ip: session.clientIp,
			origin_instance: session.originInstance,
		});
	});

	// ─── Session Management (Service API) ───────────────────────────

	/**
	 * Validate a session token hash — called by API instances during auth.
	 * This is the fast path: look up by token hash in the global store.
	 */
	app.post('/session/validate', async (ctx) => {
		if (!verifyServiceAuth(ctx.req.header('Authorization'))) {
			return ctx.json({error: 'unauthorized'}, 401);
		}

		const body = await ctx.req.json<{tokenHash: string}>();
		const session = await sessionStore.getSessionByTokenHash(body.tokenHash);

		if (!session) {
			return ctx.json({valid: false});
		}

		// Touch session periodically
		await sessionStore.touchSession(session.sessionId, SsoConfig.session.activityUpdateInterval);

		return ctx.json({
			valid: true,
			session_id: session.sessionId,
			user_id: session.userId,
			created_at: session.createdAt,
			last_active_at: session.lastActiveAt,
			origin_instance: session.originInstance,
		});
	});

	/**
	 * List all global sessions for a user.
	 */
	app.get('/session/list/:userId', async (ctx) => {
		if (!verifyServiceAuth(ctx.req.header('Authorization'))) {
			return ctx.json({error: 'unauthorized'}, 401);
		}

		const userId = ctx.req.param('userId');
		const sessions = await sessionStore.getUserSessions(userId);

		return ctx.json({
			sessions: sessions.map((s) => ({
				session_id: s.sessionId,
				user_id: s.userId,
				created_at: s.createdAt,
				last_active_at: s.lastActiveAt,
				client_ip: s.clientIp,
				user_agent: s.userAgent,
				is_desktop: s.isDesktop,
				origin_instance: s.originInstance,
			})),
		});
	});

	/**
	 * Invalidate specific session(s).
	 */
	app.post('/session/invalidate', async (ctx) => {
		if (!verifyServiceAuth(ctx.req.header('Authorization'))) {
			return ctx.json({error: 'unauthorized'}, 401);
		}

		const body = await ctx.req.json<{sessionIds: string[]}>();
		await sessionStore.invalidateSessions(body.sessionIds);

		return ctx.json({success: true});
	});

	/**
	 * Global logout — invalidate ALL sessions for a user.
	 */
	app.post('/session/invalidate-all', async (ctx) => {
		if (!verifyServiceAuth(ctx.req.header('Authorization'))) {
			return ctx.json({error: 'unauthorized'}, 401);
		}

		const body = await ctx.req.json<{userId: string}>();
		await sessionStore.invalidateAllUserSessions(body.userId);

		return ctx.json({success: true});
	});

	// ─── Revocation Endpoint ────────────────────────────────────────

	app.post('/revoke', async (ctx) => {
		const body = await ctx.req.parseBody();
		const token = body.token as string;

		if (!token) {
			return ctx.json({error: 'invalid_request'}, 400);
		}

		// Try as access token first
		const accessPayload = await tokenService.verifyAccessToken(token);
		if (accessPayload) {
			await sessionStore.invalidateSession(accessPayload.sid);
			return ctx.json({success: true});
		}

		// Try as refresh token
		const refreshData = await sessionStore.consumeRefreshToken(token);
		if (refreshData) {
			return ctx.json({success: true});
		}

		// Token already invalid — that's OK per RFC 7009
		return ctx.json({success: true});
	});

	// ─── Logout Endpoint ────────────────────────────────────────────

	app.post('/logout', async (ctx) => {
		// Clear SSO cookie
		deleteCookie(ctx, SSO_SESSION_COOKIE, {
			domain: SsoConfig.cookie.domain,
			secure: SsoConfig.cookie.secure,
			httpOnly: true,
			sameSite: 'Lax',
			path: '/',
		});

		// If service-authenticated, invalidate session by ID
		const authHeader = ctx.req.header('Authorization');
		if (verifyServiceAuth(authHeader)) {
			const body = await ctx.req.json<{sessionId?: string; userId?: string}>();
			if (body.sessionId) {
				await sessionStore.invalidateSession(body.sessionId);
			}
			if (body.userId) {
				await sessionStore.invalidateAllUserSessions(body.userId);
			}
		}

		// If user has SSO cookie, invalidate that session
		const sessionId = getCookie(ctx, SSO_SESSION_COOKIE);
		if (sessionId) {
			await sessionStore.invalidateSession(sessionId);
		}

		return ctx.json({success: true});
	});

	// ─── SSO Session Cookie ─────────────────────────────────────────
	// Set the SSO session cookie after login (called by API via redirect)

	app.post('/session/set-cookie', async (ctx) => {
		if (!verifyServiceAuth(ctx.req.header('Authorization'))) {
			return ctx.json({error: 'unauthorized'}, 401);
		}

		const body = await ctx.req.json<{sessionId: string; userId: string}>();
		const session = await sessionStore.getSession(body.sessionId);
		if (!session) {
			return ctx.json({error: 'session_not_found'}, 404);
		}

		setCookie(ctx, SSO_SESSION_COOKIE, body.sessionId, {
			domain: SsoConfig.cookie.domain,
			secure: SsoConfig.cookie.secure,
			httpOnly: true,
			sameSite: 'Lax',
			path: '/',
			maxAge: SsoConfig.session.ttl,
		});

		return ctx.json({success: true});
	});

	return app;
}
