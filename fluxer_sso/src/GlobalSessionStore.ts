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
import type {Redis} from 'ioredis';
import {Logger} from './Logger.js';

/**
 * Represents a global SSO session stored in Redis/Valkey.
 * This session is shared across ALL Fluxer server instances.
 */
export interface GlobalSsoSession {
	/** Unique session ID (UUID v4) */
	sessionId: string;
	/** Fluxer user ID */
	userId: string;
	/** SHA-256 hash of the original auth token (hex) */
	tokenHash: string;
	/** ISO timestamp when session was created */
	createdAt: string;
	/** ISO timestamp of last activity */
	lastActiveAt: string;
	/** Client IP that created the session */
	clientIp: string;
	/** User-Agent string */
	userAgent: string | null;
	/** Whether this is a desktop client session */
	isDesktop: boolean;
	/** Which API instance originated this session */
	originInstance: string;
	/** Session version for optimistic concurrency */
	version: number;
}

/**
 * PKCE authorization code stored temporarily during the auth code flow.
 */
export interface AuthorizationCode {
	code: string;
	userId: string;
	sessionId: string;
	redirectUri: string;
	codeChallenge: string;
	codeChallengeMethod: 'S256';
	clientId: string;
	scope: string;
	createdAt: string;
	expiresAt: string;
}

// Redis key prefixes
const KEY_PREFIX = 'sso:';
const SESSION_KEY = `${KEY_PREFIX}session:`;
const USER_SESSIONS_KEY = `${KEY_PREFIX}user-sessions:`;
const AUTH_CODE_KEY = `${KEY_PREFIX}auth-code:`;
const REFRESH_TOKEN_KEY = `${KEY_PREFIX}refresh-token:`;
const PKCE_CHALLENGE_KEY = `${KEY_PREFIX}pkce:`;
const TOKEN_TO_SESSION_KEY = `${KEY_PREFIX}token-session:`;

// Pub/Sub channels
export const SSO_SESSION_INVALIDATED = 'sso:session-invalidated';
export const SSO_SESSION_CREATED = 'sso:session-created';
export const SSO_GLOBAL_LOGOUT = 'sso:global-logout';

export class GlobalSessionStore {
	constructor(
		private redis: Redis,
		private sessionTtl: number,
	) {}

	/**
	 * Create a new global SSO session.
	 * This is stored in Redis so ALL API instances can validate it.
	 */
	async createSession(params: {
		userId: string;
		tokenHash: string;
		clientIp: string;
		userAgent: string | null;
		isDesktop: boolean;
		originInstance: string;
	}): Promise<GlobalSsoSession> {
		const sessionId = crypto.randomUUID();
		const now = new Date().toISOString();

		const session: GlobalSsoSession = {
			sessionId,
			userId: params.userId,
			tokenHash: params.tokenHash,
			createdAt: now,
			lastActiveAt: now,
			clientIp: params.clientIp,
			userAgent: params.userAgent,
			isDesktop: params.isDesktop,
			originInstance: params.originInstance,
			version: 1,
		};

		const pipeline = this.redis.pipeline();

		// Store the session data
		pipeline.set(
			`${SESSION_KEY}${sessionId}`,
			JSON.stringify(session),
			'EX',
			this.sessionTtl,
		);

		// Index: user → sessions (sorted set, scored by creation time)
		pipeline.zadd(
			`${USER_SESSIONS_KEY}${params.userId}`,
			Date.now(),
			sessionId,
		);
		pipeline.expire(`${USER_SESSIONS_KEY}${params.userId}`, this.sessionTtl);

		// Index: tokenHash → sessionId (for quick lookup during auth)
		pipeline.set(
			`${TOKEN_TO_SESSION_KEY}${params.tokenHash}`,
			sessionId,
			'EX',
			this.sessionTtl,
		);

		await pipeline.exec();

		// Publish session creation event for all instances
		await this.redis.publish(
			SSO_SESSION_CREATED,
			JSON.stringify({sessionId, userId: params.userId, originInstance: params.originInstance}),
		);

		Logger.info({sessionId, userId: params.userId, originInstance: params.originInstance}, 'Global SSO session created');

		return session;
	}

	/**
	 * Get a session by its ID — works from ANY server instance.
	 */
	async getSession(sessionId: string): Promise<GlobalSsoSession | null> {
		const data = await this.redis.get(`${SESSION_KEY}${sessionId}`);
		if (!data) return null;
		return JSON.parse(data) as GlobalSsoSession;
	}

	/**
	 * Look up a session by the auth token hash.
	 * This is the primary lookup path used by API instances during request auth.
	 */
	async getSessionByTokenHash(tokenHash: string): Promise<GlobalSsoSession | null> {
		const sessionId = await this.redis.get(`${TOKEN_TO_SESSION_KEY}${tokenHash}`);
		if (!sessionId) return null;
		return this.getSession(sessionId);
	}

	/**
	 * List all active sessions for a user across ALL instances.
	 */
	async getUserSessions(userId: string): Promise<GlobalSsoSession[]> {
		const sessionIds = await this.redis.zrange(`${USER_SESSIONS_KEY}${userId}`, 0, -1);
		if (sessionIds.length === 0) return [];

		const pipeline = this.redis.pipeline();
		for (const sid of sessionIds) {
			pipeline.get(`${SESSION_KEY}${sid}`);
		}

		const results = await pipeline.exec();
		if (!results) return [];

		const sessions: GlobalSsoSession[] = [];
		const expiredSessionIds: string[] = [];

		for (let i = 0; i < results.length; i++) {
			const [err, data] = results[i]!;
			if (err || !data) {
				// Session expired from Redis but still in the set — clean up
				expiredSessionIds.push(sessionIds[i]!);
				continue;
			}
			sessions.push(JSON.parse(data as string) as GlobalSsoSession);
		}

		// Remove expired entries from the user sessions set
		if (expiredSessionIds.length > 0) {
			await this.redis.zrem(`${USER_SESSIONS_KEY}${userId}`, ...expiredSessionIds);
		}

		return sessions;
	}

	/**
	 * Touch a session — update lastActiveAt.
	 * Debounced: only updates if more than `interval` seconds since last update.
	 */
	async touchSession(sessionId: string, interval: number): Promise<void> {
		const session = await this.getSession(sessionId);
		if (!session) return;

		const lastActive = new Date(session.lastActiveAt).getTime();
		const now = Date.now();
		if (now - lastActive < interval * 1000) return;

		session.lastActiveAt = new Date(now).toISOString();
		session.version += 1;

		await this.redis.set(
			`${SESSION_KEY}${sessionId}`,
			JSON.stringify(session),
			'EX',
			this.sessionTtl,
		);
	}

	/**
	 * Invalidate a single session — notifies ALL instances via pub/sub.
	 */
	async invalidateSession(sessionId: string): Promise<void> {
		const session = await this.getSession(sessionId);
		if (!session) return;

		const pipeline = this.redis.pipeline();
		pipeline.del(`${SESSION_KEY}${sessionId}`);
		pipeline.del(`${TOKEN_TO_SESSION_KEY}${session.tokenHash}`);
		pipeline.zrem(`${USER_SESSIONS_KEY}${session.userId}`, sessionId);
		await pipeline.exec();

		// Notify all API instances to clear their local caches
		await this.redis.publish(
			SSO_SESSION_INVALIDATED,
			JSON.stringify({sessionId, userId: session.userId, tokenHash: session.tokenHash}),
		);

		Logger.info({sessionId, userId: session.userId}, 'Global SSO session invalidated');
	}

	/**
	 * Invalidate specific sessions by their IDs.
	 */
	async invalidateSessions(sessionIds: string[]): Promise<void> {
		for (const sessionId of sessionIds) {
			await this.invalidateSession(sessionId);
		}
	}

	/**
	 * Global logout — invalidate ALL sessions for a user across ALL instances.
	 */
	async invalidateAllUserSessions(userId: string): Promise<void> {
		const sessions = await this.getUserSessions(userId);

		if (sessions.length === 0) return;

		const pipeline = this.redis.pipeline();
		for (const session of sessions) {
			pipeline.del(`${SESSION_KEY}${session.sessionId}`);
			pipeline.del(`${TOKEN_TO_SESSION_KEY}${session.tokenHash}`);
		}
		pipeline.del(`${USER_SESSIONS_KEY}${userId}`);
		await pipeline.exec();

		// Notify all instances
		await this.redis.publish(
			SSO_GLOBAL_LOGOUT,
			JSON.stringify({
				userId,
				sessionIds: sessions.map((s) => s.sessionId),
				tokenHashes: sessions.map((s) => s.tokenHash),
			}),
		);

		Logger.info({userId, count: sessions.length}, 'All global SSO sessions invalidated');
	}

	// ─── Authorization Code (PKCE) ───────────────────────────────────

	/**
	 * Store a PKCE authorization code (short-lived, 5 minutes).
	 */
	async storeAuthorizationCode(authCode: AuthorizationCode): Promise<void> {
		await this.redis.set(
			`${AUTH_CODE_KEY}${authCode.code}`,
			JSON.stringify(authCode),
			'EX',
			300, // 5 minutes
		);
	}

	/**
	 * Consume an authorization code (one-time use).
	 */
	async consumeAuthorizationCode(code: string): Promise<AuthorizationCode | null> {
		const key = `${AUTH_CODE_KEY}${code}`;
		const data = await this.redis.get(key);
		if (!data) return null;

		// Delete immediately — codes are single-use
		await this.redis.del(key);

		return JSON.parse(data) as AuthorizationCode;
	}

	// ─── Refresh Tokens ──────────────────────────────────────────────

	/**
	 * Store a refresh token mapping to a session.
	 */
	async storeRefreshToken(params: {
		refreshToken: string;
		sessionId: string;
		userId: string;
		ttl: number;
	}): Promise<void> {
		await this.redis.set(
			`${REFRESH_TOKEN_KEY}${params.refreshToken}`,
			JSON.stringify({
				sessionId: params.sessionId,
				userId: params.userId,
				createdAt: new Date().toISOString(),
			}),
			'EX',
			params.ttl,
		);
	}

	/**
	 * Consume a refresh token (one-time use, rotation).
	 */
	async consumeRefreshToken(refreshToken: string): Promise<{sessionId: string; userId: string} | null> {
		const key = `${REFRESH_TOKEN_KEY}${refreshToken}`;
		const data = await this.redis.get(key);
		if (!data) return null;

		await this.redis.del(key);

		const parsed = JSON.parse(data) as {sessionId: string; userId: string};
		return parsed;
	}

	// ─── PKCE Challenge ──────────────────────────────────────────────

	/**
	 * Store a PKCE code challenge for the authorize flow.
	 */
	async storePkceChallenge(state: string, params: {
		codeChallenge: string;
		codeChallengeMethod: 'S256';
		clientId: string;
		redirectUri: string;
		scope: string;
	}): Promise<void> {
		await this.redis.set(
			`${PKCE_CHALLENGE_KEY}${state}`,
			JSON.stringify(params),
			'EX',
			600, // 10 minutes
		);
	}

	/**
	 * Retrieve and consume a PKCE challenge.
	 */
	async consumePkceChallenge(state: string): Promise<{
		codeChallenge: string;
		codeChallengeMethod: 'S256';
		clientId: string;
		redirectUri: string;
		scope: string;
	} | null> {
		const key = `${PKCE_CHALLENGE_KEY}${state}`;
		const data = await this.redis.get(key);
		if (!data) return null;

		await this.redis.del(key);
		return JSON.parse(data);
	}
}
