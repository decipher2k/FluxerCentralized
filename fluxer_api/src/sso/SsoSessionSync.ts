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

import {Logger} from '~/Logger';
import type {AuthSession} from '~/Models';
import {getSsoClient} from './SsoClientSingleton';

/**
 * SSO Session Sync — hooks into the existing auth flow to keep the
 * global SSO session store in sync with local Cassandra sessions.
 *
 * After a successful local login/registration that creates an auth session,
 * this module registers the session globally so all API instances can validate it.
 *
 * After a logout/revocation, this module invalidates the session globally.
 */

/**
 * Register a newly created auth session with the global SSO server.
 * Called after AuthSessionService.createAuthSession().
 */
export async function syncSessionToSso(params: {
	authSession: AuthSession;
	request: Request;
}): Promise<void> {
	const ssoClient = getSsoClient();
	if (!ssoClient) return; // SSO not configured

	try {
		const clientIp = params.request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';
		const userAgent = params.request.headers.get('user-agent') || null;
		const isDesktop = params.request.headers.get('x-fluxer-platform')?.trim().toLowerCase() === 'desktop';
		const tokenHash = Buffer.from(params.authSession.sessionIdHash).toString('hex');

		await ssoClient.createGlobalSession({
			userId: params.authSession.userId.toString(),
			tokenHash,
			clientIp,
			userAgent,
			isDesktop,
		});

		Logger.debug(
			{userId: params.authSession.userId.toString()},
			'Auth session synced to global SSO store',
		);
	} catch (error) {
		// Don't fail the login if SSO sync fails — local session is still valid
		Logger.error({error}, 'Failed to sync auth session to SSO server');
	}
}

/**
 * Invalidate a session in the global SSO store.
 * Called after AuthSessionService.revokeToken() or logoutAuthSessions().
 */
export async function invalidateSessionInSso(params: {
	sessionIdHash: Buffer;
}): Promise<void> {
	const ssoClient = getSsoClient();
	if (!ssoClient) return;

	try {
		const tokenHash = params.sessionIdHash.toString('hex');
		// We need to look up the SSO session ID by token hash, then invalidate it
		const result = await ssoClient.validateSession(tokenHash);
		if (result.valid && result.session_id) {
			await ssoClient.invalidateSessions([result.session_id]);
		}
	} catch (error) {
		Logger.error({error}, 'Failed to invalidate session in SSO server');
	}
}

/**
 * Invalidate ALL sessions for a user in the global SSO store.
 * Called after AuthSessionService.terminateAllUserSessions().
 */
export async function invalidateAllUserSessionsInSso(userId: string): Promise<void> {
	const ssoClient = getSsoClient();
	if (!ssoClient) return;

	try {
		await ssoClient.invalidateAllUserSessions(userId);
	} catch (error) {
		Logger.error({error, userId}, 'Failed to invalidate all user sessions in SSO server');
	}
}
