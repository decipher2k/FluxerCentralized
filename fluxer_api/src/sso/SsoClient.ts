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
import * as jose from 'jose';
import {Logger} from '~/Logger';

/**
 * SSO Client — used by each API instance to communicate with the central SSO server.
 *
 * Key capabilities:
 * - Register new sessions with the SSO server on login
 * - Validate session tokens against the global session store
 * - Verify SSO JWTs locally using the cached public key (JWKS)
 * - Manage global session lifecycle (logout, invalidation)
 */
export class SsoClient {
	private jwksPublicKey: jose.KeyLike | null = null;
	private jwksLastFetched = 0;
	private readonly JWKS_CACHE_TTL = 3600_000; // 1 hour

	constructor(
		private ssoServerUrl: string,
		private serviceSecret: string,
		private instanceId: string,
	) {}

	private get authHeaders(): Record<string, string> {
		return {
			'Authorization': `Service ${this.serviceSecret}`,
			'Content-Type': 'application/json',
		};
	}

	/**
	 * Initialize by fetching the JWKS from the SSO server.
	 * Allows this API instance to verify SSO JWTs locally without
	 * contacting the SSO server on every request.
	 */
	async initialize(): Promise<void> {
		await this.refreshJwks();
		Logger.info({ssoServerUrl: this.ssoServerUrl}, 'SSO client initialized');
	}

	/**
	 * Fetch the JWKS from the SSO server.
	 */
	private async refreshJwks(): Promise<void> {
		try {
			const response = await fetch(`${this.ssoServerUrl}/.well-known/jwks.json`);
			if (!response.ok) {
				throw new Error(`JWKS fetch failed: ${response.status}`);
			}

			const jwks = (await response.json()) as {keys: jose.JWK[]};
			if (jwks.keys.length > 0) {
				this.jwksPublicKey = await jose.importJWK(jwks.keys[0]!, 'RS256');
				this.jwksLastFetched = Date.now();
				Logger.info('SSO JWKS refreshed');
			}
		} catch (error) {
			Logger.error({error}, 'Failed to fetch SSO JWKS');
		}
	}

	/**
	 * Get the public key for verifying SSO JWTs.
	 * Auto-refreshes if the cached key is stale.
	 */
	private async getPublicKey(): Promise<jose.KeyLike | null> {
		if (!this.jwksPublicKey || Date.now() - this.jwksLastFetched > this.JWKS_CACHE_TTL) {
			await this.refreshJwks();
		}
		return this.jwksPublicKey;
	}

	// ─── Session Management ─────────────────────────────────────────

	/**
	 * Register a new session with the SSO server after local login.
	 * Called when a user successfully authenticates on this API instance.
	 */
	async createGlobalSession(params: {
		userId: string;
		tokenHash: string;
		clientIp: string;
		userAgent: string | null;
		isDesktop: boolean;
		state?: string;
	}): Promise<{
		session_id: string;
		user_id: string;
		created_at: string;
		auth_code?: string;
	}> {
		const response = await fetch(`${this.ssoServerUrl}/session/create`, {
			method: 'POST',
			headers: this.authHeaders,
			body: JSON.stringify({
				...params,
				originInstance: this.instanceId,
			}),
		});

		if (!response.ok) {
			const err = await response.text();
			Logger.error({status: response.status, body: err}, 'Failed to create global SSO session');
			throw new Error(`SSO session creation failed: ${response.status}`);
		}

		return response.json() as Promise<{
			session_id: string;
			user_id: string;
			created_at: string;
			auth_code?: string;
		}>;
	}

	/**
	 * Validate a session token hash against the global session store.
	 * This is the primary auth path — called on every authenticated request.
	 */
	async validateSession(tokenHash: string): Promise<{
		valid: boolean;
		session_id?: string;
		user_id?: string;
		created_at?: string;
		last_active_at?: string;
		origin_instance?: string;
	}> {
		const response = await fetch(`${this.ssoServerUrl}/session/validate`, {
			method: 'POST',
			headers: this.authHeaders,
			body: JSON.stringify({tokenHash}),
		});

		if (!response.ok) {
			Logger.warn({status: response.status}, 'SSO session validation request failed');
			return {valid: false};
		}

		return response.json() as Promise<{
			valid: boolean;
			session_id?: string;
			user_id?: string;
			created_at?: string;
			last_active_at?: string;
			origin_instance?: string;
		}>;
	}

	/**
	 * List all sessions for a user across all instances.
	 */
	async listUserSessions(userId: string): Promise<Array<{
		session_id: string;
		user_id: string;
		created_at: string;
		last_active_at: string;
		client_ip: string;
		user_agent: string | null;
		is_desktop: boolean;
		origin_instance: string;
	}>> {
		const response = await fetch(`${this.ssoServerUrl}/session/list/${userId}`, {
			headers: this.authHeaders,
		});

		if (!response.ok) {
			Logger.warn({status: response.status}, 'SSO list sessions request failed');
			return [];
		}

		const data = await response.json() as {sessions: Array<{
			session_id: string;
			user_id: string;
			created_at: string;
			last_active_at: string;
			client_ip: string;
			user_agent: string | null;
			is_desktop: boolean;
			origin_instance: string;
		}>};
		return data.sessions;
	}

	/**
	 * Invalidate specific sessions.
	 */
	async invalidateSessions(sessionIds: string[]): Promise<void> {
		const response = await fetch(`${this.ssoServerUrl}/session/invalidate`, {
			method: 'POST',
			headers: this.authHeaders,
			body: JSON.stringify({sessionIds}),
		});

		if (!response.ok) {
			Logger.warn({status: response.status}, 'SSO session invalidation failed');
		}
	}

	/**
	 * Global logout — invalidate ALL sessions for a user.
	 */
	async invalidateAllUserSessions(userId: string): Promise<void> {
		const response = await fetch(`${this.ssoServerUrl}/session/invalidate-all`, {
			method: 'POST',
			headers: this.authHeaders,
			body: JSON.stringify({userId}),
		});

		if (!response.ok) {
			Logger.warn({status: response.status}, 'SSO global logout failed');
		}
	}

	// ─── JWT Verification (Local) ───────────────────────────────────

	/**
	 * Verify an SSO access token locally using the cached JWKS.
	 * No round-trip to the SSO server needed!
	 */
	async verifyAccessToken(token: string): Promise<{
		userId: string;
		sessionId: string;
		scope: string;
	} | null> {
		const publicKey = await this.getPublicKey();
		if (!publicKey) return null;

		try {
			const {payload} = await jose.jwtVerify(token, publicKey, {
				algorithms: ['RS256'],
			});

			if (payload.type !== 'access') return null;

			return {
				userId: payload.sub!,
				sessionId: payload.sid as string,
				scope: (payload.scope as string) || 'identify',
			};
		} catch {
			return null;
		}
	}

	// ─── PKCE Helpers ───────────────────────────────────────────────

	/**
	 * Generate a PKCE code verifier and challenge for the auth code flow.
	 */
	static generatePkceChallenge(): {codeVerifier: string; codeChallenge: string} {
		const codeVerifier = crypto.randomBytes(32).toString('base64url');
		const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
		return {codeVerifier, codeChallenge};
	}

	/**
	 * Exchange an authorization code for tokens via the SSO server.
	 */
	async exchangeAuthCode(params: {
		code: string;
		codeVerifier: string;
		redirectUri: string;
	}): Promise<{
		access_token: string;
		token_type: string;
		expires_in: number;
		refresh_token: string;
		scope?: string;
		session_id?: string;
	}> {
		const body = new URLSearchParams({
			grant_type: 'authorization_code',
			code: params.code,
			code_verifier: params.codeVerifier,
			redirect_uri: params.redirectUri,
		});

		const response = await fetch(`${this.ssoServerUrl}/token`, {
			method: 'POST',
			headers: {'Content-Type': 'application/x-www-form-urlencoded'},
			body: body.toString(),
		});

		if (!response.ok) {
			const err = await response.text();
			throw new Error(`Token exchange failed: ${response.status} ${err}`);
		}

		return response.json() as Promise<{
			access_token: string;
			token_type: string;
			expires_in: number;
			refresh_token: string;
			scope?: string;
			session_id?: string;
		}>;
	}

	/**
	 * Refresh an access token using a refresh token.
	 */
	async refreshAccessToken(refreshToken: string): Promise<{
		access_token: string;
		token_type: string;
		expires_in: number;
		refresh_token: string;
	}> {
		const body = new URLSearchParams({
			grant_type: 'refresh_token',
			refresh_token: refreshToken,
		});

		const response = await fetch(`${this.ssoServerUrl}/token`, {
			method: 'POST',
			headers: {'Content-Type': 'application/x-www-form-urlencoded'},
			body: body.toString(),
		});

		if (!response.ok) {
			const err = await response.text();
			throw new Error(`Token refresh failed: ${response.status} ${err}`);
		}

		return response.json() as Promise<{
			access_token: string;
			token_type: string;
			expires_in: number;
			refresh_token: string;
		}>;
	}
}
