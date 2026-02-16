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

import {createMiddleware} from 'hono/factory';
import type {HonoEnv} from '~/App';
import {Config} from '~/Config';
import {Logger} from '~/Logger';
import {getSsoClient} from '~/sso/SsoClientSingleton';

/**
 * SSO Session Middleware.
 *
 * This middleware enhances session authentication to use the global SSO session store.
 * It intercepts after the standard UserMiddleware has parsed the auth token, and
 * validates the session against the central SSO server.
 *
 * Behavior:
 * - If SSO is disabled (no SSO_SERVER_URL), passes through unchanged.
 * - If the auth token is a 'session' type, validates it against the global SSO session store.
 * - If the global session is invalid but local Cassandra session exists, the session
 *   is considered invalid (SSO server is the source of truth).
 * - For 'bearer' and 'bot' token types, behavior is unchanged.
 *
 * This ensures that a session created on Instance A is valid on Instance B,
 * and a logout on Instance A immediately invalidates on Instance B.
 */
export const SsoSessionMiddleware = createMiddleware<HonoEnv>(async (ctx, next) => {
	const ssoClient = getSsoClient();

	// If SSO is not configured, pass through
	if (!ssoClient) {
		return next();
	}

	const authTokenType = ctx.get('authTokenType');

	// Only intercept session-type auth tokens
	if (authTokenType !== 'session') {
		return next();
	}

	const authToken = ctx.get('authToken');
	if (!authToken) {
		return next();
	}

	// Check bearer-style SSO JWT first (for cross-instance calls)
	if (authToken.startsWith('eyJ')) {
		const ssoPayload = await ssoClient.verifyAccessToken(authToken);
		if (ssoPayload) {
			// Valid SSO JWT — set the user context
			ctx.set('authUserId', ssoPayload.userId);
			ctx.set('ssoSessionId' as never, ssoPayload.sessionId);
			return next();
		}
	}

	// For regular flx_ tokens, the UserMiddleware already validated against Cassandra.
	// Now additionally validate against the global SSO session store.
	const authSession = ctx.get('authSession');
	if (authSession) {
		try {
			const tokenHash = Buffer.from(authSession.sessionIdHash).toString('hex');
			const ssoResult = await ssoClient.validateSession(tokenHash);

			if (!ssoResult.valid) {
				// Session exists in Cassandra but NOT in the global SSO store.
				// This means it was invalidated globally (e.g., logout from another instance).
				Logger.info(
					{userId: authSession.userId, tokenHash},
					'Session rejected: not found in global SSO store',
				);

				// Clear the auth context — request becomes unauthenticated
				ctx.set('user', undefined as never);
				ctx.set('authSession', undefined as never);
				ctx.set('authTokenType', undefined);
				ctx.set('authToken', undefined);
			}
		} catch (error) {
			// If the SSO server is unreachable, fall back to local Cassandra validation.
			// This ensures the system degrades gracefully.
			Logger.warn({error}, 'SSO server unreachable, falling back to local session validation');
		}
	}

	return next();
});
