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

import http from '~/lib/HttpClient';
import {Logger} from '~/lib/Logger';
import AppStorage from '~/lib/AppStorage';

const logger = new Logger('SsoService');

const SSO_STORAGE_KEYS = {
	AccessToken: 'sso_access_token',
	RefreshToken: 'sso_refresh_token',
	SessionId: 'sso_session_id',
	ExpiresAt: 'sso_expires_at',
	CodeVerifier: 'sso_code_verifier',
	State: 'sso_state',
} as const;

export interface SsoConfig {
	enabled: boolean;
	sso_server_url: string | null;
	authorize_endpoint: string | null;
	token_endpoint: string | null;
	jwks_uri: string | null;
}

export interface SsoTokens {
	access_token: string;
	token_type: string;
	expires_in: number;
	refresh_token: string;
	scope?: string;
	session_id?: string;
}

export interface SsoGlobalSession {
	session_id: string;
	user_id: string;
	created_at: string;
	last_active_at: string;
	client_ip: string;
	user_agent: string | null;
	is_desktop: boolean;
	origin_instance: string;
}

/**
 * SSO Service for the Fluxer frontend app.
 *
 * Handles:
 * - PKCE authorization flow initiation
 * - Auth code exchange for tokens
 * - Automatic token refresh before expiry
 * - Global session management (list, invalidate, logout-all)
 * - SSO configuration discovery
 */
class SsoService {
	private _config: SsoConfig | null = null;
	private _refreshTimer: ReturnType<typeof setTimeout> | null = null;

	/**
	 * Fetch SSO configuration from the API.
	 */
	async getConfig(): Promise<SsoConfig> {
		if (this._config) return this._config;

		try {
			const response = await http.get<SsoConfig>({url: '/sso/config'});
			this._config = response.body;
			return this._config;
		} catch (error) {
			logger.warn('Failed to fetch SSO config', error);
			return {enabled: false, sso_server_url: null, authorize_endpoint: null, token_endpoint: null, jwks_uri: null};
		}
	}

	/**
	 * Check if SSO is enabled on the current instance.
	 */
	async isEnabled(): Promise<boolean> {
		const config = await this.getConfig();
		return config.enabled;
	}

	// ─── PKCE Authorization Flow ────────────────────────────────────

	/**
	 * Start the SSO authorization flow.
	 * Returns the authorize URL the client should redirect to.
	 */
	async initiateAuthorize(redirectUri?: string): Promise<{
		authorizeUrl: string;
		state: string;
		codeVerifier: string;
	}> {
		const response = await http.get<{
			authorize_url: string;
			state: string;
			code_verifier: string;
		}>({
			url: '/sso/authorize',
			query: redirectUri ? {redirect_uri: redirectUri} : undefined,
		});

		// Store PKCE state for the callback
		AppStorage.setItem(SSO_STORAGE_KEYS.CodeVerifier, response.body.code_verifier);
		AppStorage.setItem(SSO_STORAGE_KEYS.State, response.body.state);

		return {
			authorizeUrl: response.body.authorize_url,
			state: response.body.state,
			codeVerifier: response.body.code_verifier,
		};
	}

	/**
	 * Handle the SSO callback — exchange the auth code for tokens.
	 */
	async handleCallback(params: {
		code: string;
		state: string;
		redirectUri: string;
	}): Promise<SsoTokens> {
		const storedState = AppStorage.getItem(SSO_STORAGE_KEYS.State);
		const codeVerifier = AppStorage.getItem(SSO_STORAGE_KEYS.CodeVerifier);

		if (!storedState || storedState !== params.state) {
			throw new Error('SSO state mismatch — possible CSRF attack');
		}

		if (!codeVerifier) {
			throw new Error('Missing PKCE code verifier');
		}

		const response = await http.post<SsoTokens>({
			url: '/sso/callback',
			body: {
				code: params.code,
				code_verifier: codeVerifier,
				redirect_uri: params.redirectUri,
				state: params.state,
			},
		});

		const tokens = response.body;

		// Store tokens
		this.storeTokens(tokens);

		// Clean up PKCE state
		AppStorage.removeItem(SSO_STORAGE_KEYS.CodeVerifier);
		AppStorage.removeItem(SSO_STORAGE_KEYS.State);

		// Schedule automatic refresh
		this.scheduleRefresh(tokens.expires_in);

		logger.info('SSO tokens obtained successfully');
		return tokens;
	}

	// ─── Token Management ───────────────────────────────────────────

	/**
	 * Get the current SSO access token, refreshing if necessary.
	 */
	async getAccessToken(): Promise<string | null> {
		const accessToken = AppStorage.getItem(SSO_STORAGE_KEYS.AccessToken);
		const expiresAt = AppStorage.getItem(SSO_STORAGE_KEYS.ExpiresAt);

		if (!accessToken) return null;

		// Refresh if expiring within 60 seconds
		if (expiresAt && Date.now() > Number(expiresAt) - 60_000) {
			try {
				const refreshed = await this.refreshTokens();
				return refreshed?.access_token ?? null;
			} catch {
				return null;
			}
		}

		return accessToken;
	}

	/**
	 * Refresh the SSO tokens using the stored refresh token.
	 */
	async refreshTokens(): Promise<SsoTokens | null> {
		const refreshToken = AppStorage.getItem(SSO_STORAGE_KEYS.RefreshToken);
		if (!refreshToken) return null;

		try {
			const response = await http.post<SsoTokens>({
				url: '/sso/refresh',
				body: {refresh_token: refreshToken},
			});

			const tokens = response.body;
			this.storeTokens(tokens);
			this.scheduleRefresh(tokens.expires_in);

			logger.debug('SSO tokens refreshed');
			return tokens;
		} catch (error) {
			logger.warn('Failed to refresh SSO tokens', error);
			this.clearTokens();
			return null;
		}
	}

	/**
	 * Store SSO tokens in local storage.
	 */
	private storeTokens(tokens: SsoTokens): void {
		AppStorage.setItem(SSO_STORAGE_KEYS.AccessToken, tokens.access_token);
		AppStorage.setItem(SSO_STORAGE_KEYS.RefreshToken, tokens.refresh_token);
		AppStorage.setItem(SSO_STORAGE_KEYS.ExpiresAt, String(Date.now() + tokens.expires_in * 1000));

		if (tokens.session_id) {
			AppStorage.setItem(SSO_STORAGE_KEYS.SessionId, tokens.session_id);
		}
	}

	/**
	 * Clear all stored SSO tokens.
	 */
	clearTokens(): void {
		AppStorage.removeItem(SSO_STORAGE_KEYS.AccessToken);
		AppStorage.removeItem(SSO_STORAGE_KEYS.RefreshToken);
		AppStorage.removeItem(SSO_STORAGE_KEYS.SessionId);
		AppStorage.removeItem(SSO_STORAGE_KEYS.ExpiresAt);
		AppStorage.removeItem(SSO_STORAGE_KEYS.CodeVerifier);
		AppStorage.removeItem(SSO_STORAGE_KEYS.State);

		if (this._refreshTimer) {
			clearTimeout(this._refreshTimer);
			this._refreshTimer = null;
		}
	}

	/**
	 * Schedule automatic token refresh before expiry.
	 */
	private scheduleRefresh(expiresIn: number): void {
		if (this._refreshTimer) {
			clearTimeout(this._refreshTimer);
		}

		// Refresh 60 seconds before expiry
		const refreshIn = Math.max((expiresIn - 60) * 1000, 10_000);
		this._refreshTimer = setTimeout(() => {
			void this.refreshTokens();
		}, refreshIn);
	}

	// ─── Global Session Management ──────────────────────────────────

	/**
	 * Get all active sessions across ALL server instances.
	 */
	async getGlobalSessions(): Promise<SsoGlobalSession[]> {
		const response = await http.get<{sessions: SsoGlobalSession[]}>({url: '/sso/sessions'});
		return response.body.sessions;
	}

	/**
	 * Invalidate specific sessions across all instances.
	 */
	async invalidateSessions(sessionIds: string[]): Promise<void> {
		await http.post({
			url: '/sso/sessions/invalidate',
			body: {session_ids: sessionIds},
		});
	}

	/**
	 * Global logout — invalidate ALL sessions on ALL instances.
	 */
	async globalLogout(): Promise<void> {
		await http.post({url: '/sso/logout-all'});
		this.clearTokens();
	}

	/**
	 * Get the current global session ID.
	 */
	getSessionId(): string | null {
		return AppStorage.getItem(SSO_STORAGE_KEYS.SessionId);
	}

	/**
	 * Check if we have valid SSO tokens.
	 */
	hasValidTokens(): boolean {
		const accessToken = AppStorage.getItem(SSO_STORAGE_KEYS.AccessToken);
		const refreshToken = AppStorage.getItem(SSO_STORAGE_KEYS.RefreshToken);
		return !!(accessToken || refreshToken);
	}
}

export default new SsoService();
