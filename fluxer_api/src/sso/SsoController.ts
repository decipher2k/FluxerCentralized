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

import {randomUUID} from 'node:crypto';
import type {HonoApp} from '~/App';
import {Config} from '~/Config';
import {UnauthorizedError} from '~/Errors';
import {LoginRequired} from '~/middleware/AuthMiddleware';
import {z} from '~/Schema';
import {getSsoClient} from '~/sso/SsoClientSingleton';
import {SsoClient} from '~/sso/SsoClient';
import {Validator} from '~/Validator';

/**
 * SSO Controller — API-side endpoints for the SSO auth code flow.
 *
 * These endpoints allow:
 * - Initiating the SSO authorization flow (PKCE)
 * - Handling the SSO callback (auth code exchange)
 * - Listing global sessions across all instances
 * - Global session management (invalidation, logout)
 */

const SsoCallbackRequest = z.object({
	code: z.string(),
	code_verifier: z.string(),
	redirect_uri: z.string(),
	state: z.string(),
});

const SsoRefreshRequest = z.object({
	refresh_token: z.string(),
});

const SsoInvalidateRequest = z.object({
	session_ids: z.array(z.string()),
});

export const SsoController = (app: HonoApp) => {
	// ─── SSO Configuration ──────────────────────────────────────────
	// Returns SSO configuration info for the client app.

	app.get('/sso/config', (ctx) => {
		const ssoEnabled = Config.sso.enabled;
		const ssoServerUrl = Config.sso.serverUrl;

		return ctx.json({
			enabled: ssoEnabled,
			sso_server_url: ssoServerUrl || null,
			authorize_endpoint: ssoServerUrl ? `${ssoServerUrl}/authorize` : null,
			token_endpoint: ssoServerUrl ? `${ssoServerUrl}/token` : null,
			jwks_uri: ssoServerUrl ? `${ssoServerUrl}/.well-known/jwks.json` : null,
		});
	});

	// ─── SSO Authorization Initiation ───────────────────────────────
	// Client calls this to start the SSO flow. Returns the authorize URL
	// with PKCE parameters that the client should redirect to.

	app.get('/sso/authorize', async (ctx) => {
		const ssoClient = getSsoClient();
		if (!ssoClient) {
			return ctx.json({error: 'SSO is not configured on this instance'}, 503);
		}

		const ssoServerUrl = Config.sso.serverUrl;
		if (!ssoServerUrl) {
			return ctx.json({error: 'SSO server URL not configured'}, 503);
		}

		const redirectUri = ctx.req.query('redirect_uri') || `${Config.endpoints.apiPublic}/sso/callback`;
		const scope = ctx.req.query('scope') || 'identify';

		// Generate PKCE challenge
		const {codeVerifier, codeChallenge} = SsoClient.generatePkceChallenge();

		// Generate state parameter to prevent CSRF
		const state = randomUUID();

		const authorizeUrl = new URL(`${ssoServerUrl}/authorize`);
		authorizeUrl.searchParams.set('response_type', 'code');
		authorizeUrl.searchParams.set('client_id', 'fluxer-api');
		authorizeUrl.searchParams.set('redirect_uri', redirectUri);
		authorizeUrl.searchParams.set('code_challenge', codeChallenge);
		authorizeUrl.searchParams.set('code_challenge_method', 'S256');
		authorizeUrl.searchParams.set('scope', scope);
		authorizeUrl.searchParams.set('state', state);

		return ctx.json({
			authorize_url: authorizeUrl.toString(),
			state,
			code_verifier: codeVerifier, // Client stores this for the callback
		});
	});

	// ─── SSO Callback ───────────────────────────────────────────────
	// After the SSO server authenticates the user and issues an auth code,
	// the client calls this endpoint to exchange it for tokens.

	app.post('/sso/callback', Validator('json', SsoCallbackRequest), async (ctx) => {
		const ssoClient = getSsoClient();
		if (!ssoClient) {
			return ctx.json({error: 'SSO is not configured on this instance'}, 503);
		}

		const body = ctx.req.valid('json');

		try {
			const tokens = await ssoClient.exchangeAuthCode({
				code: body.code,
				codeVerifier: body.code_verifier,
				redirectUri: body.redirect_uri,
			});

			return ctx.json({
				access_token: tokens.access_token,
				token_type: tokens.token_type,
				expires_in: tokens.expires_in,
				refresh_token: tokens.refresh_token,
				scope: tokens.scope,
				session_id: tokens.session_id,
			});
		} catch {
			return ctx.json({error: 'Token exchange failed'}, 400);
		}
	});

	// ─── SSO Token Refresh ──────────────────────────────────────────

	app.post('/sso/refresh', Validator('json', SsoRefreshRequest), async (ctx) => {
		const ssoClient = getSsoClient();
		if (!ssoClient) {
			return ctx.json({error: 'SSO is not configured on this instance'}, 503);
		}

		const body = ctx.req.valid('json');

		try {
			const tokens = await ssoClient.refreshAccessToken(body.refresh_token);

			return ctx.json({
				access_token: tokens.access_token,
				token_type: tokens.token_type,
				expires_in: tokens.expires_in,
				refresh_token: tokens.refresh_token,
			});
		} catch {
			return ctx.json({error: 'Token refresh failed'}, 400);
		}
	});

	// ─── Global Sessions List ───────────────────────────────────────
	// Lists ALL sessions for the current user across ALL server instances.

	app.get('/sso/sessions', LoginRequired, async (ctx) => {
		const ssoClient = getSsoClient();
		if (!ssoClient) {
			return ctx.json({error: 'SSO is not configured on this instance'}, 503);
		}

		const user = ctx.get('user');
		if (!user) throw new UnauthorizedError();

		const sessions = await ssoClient.listUserSessions(user.id.toString());

		return ctx.json({sessions});
	});

	// ─── Global Session Invalidation ────────────────────────────────
	// Invalidate specific sessions across all instances.

	app.post('/sso/sessions/invalidate', LoginRequired, Validator('json', SsoInvalidateRequest), async (ctx) => {
		const ssoClient = getSsoClient();
		if (!ssoClient) {
			return ctx.json({error: 'SSO is not configured on this instance'}, 503);
		}

		const user = ctx.get('user');
		if (!user) throw new UnauthorizedError();

		const body = ctx.req.valid('json');
		await ssoClient.invalidateSessions(body.session_ids);

		return ctx.json({success: true});
	});

	// ─── Global Logout ──────────────────────────────────────────────
	// Logout from ALL instances simultaneously.

	app.post('/sso/logout-all', LoginRequired, async (ctx) => {
		const ssoClient = getSsoClient();
		if (!ssoClient) {
			return ctx.json({error: 'SSO is not configured on this instance'}, 503);
		}

		const user = ctx.get('user');
		if (!user) throw new UnauthorizedError();

		await ssoClient.invalidateAllUserSessions(user.id.toString());

		return ctx.json({success: true});
	});
};
