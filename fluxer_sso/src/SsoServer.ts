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

import {serve} from '@hono/node-server';
import {Hono} from 'hono';
import {logger} from 'hono/logger';
import {Redis} from 'ioredis';
import {SsoConfig} from './SsoConfig.js';
import {GlobalSessionStore, SSO_SESSION_INVALIDATED, SSO_SESSION_CREATED, SSO_GLOBAL_LOGOUT} from './GlobalSessionStore.js';
import {SsoTokenService} from './SsoTokenService.js';
import {createSsoRoutes} from './SsoRoutes.js';
import {Logger} from './Logger.js';

// ─── Initialize Redis connections ────────────────────────────────

const redis = new Redis(SsoConfig.redis.url);
const subscriber = new Redis(SsoConfig.redis.url);

// ─── Initialize services ────────────────────────────────────────

const sessionStore = new GlobalSessionStore(redis, SsoConfig.session.ttl);

const tokenService = new SsoTokenService(
	SsoConfig.jwt.privateKey,
	SsoConfig.jwt.publicKey,
	SsoConfig.jwt.issuer,
	SsoConfig.jwt.accessTokenTtl,
	SsoConfig.jwt.refreshTokenTtl,
);

await tokenService.initialize();

// ─── Subscribe to session events (for logging and monitoring) ───

await subscriber.subscribe(SSO_SESSION_INVALIDATED, SSO_SESSION_CREATED, SSO_GLOBAL_LOGOUT);

subscriber.on('message', (channel, message) => {
	try {
		const data = JSON.parse(message);
		switch (channel) {
			case SSO_SESSION_CREATED:
				Logger.info({...data}, 'SSO event: session created');
				break;
			case SSO_SESSION_INVALIDATED:
				Logger.info({...data}, 'SSO event: session invalidated');
				break;
			case SSO_GLOBAL_LOGOUT:
				Logger.info({userId: data.userId, sessionCount: data.sessionIds?.length}, 'SSO event: global logout');
				break;
		}
	} catch {
		Logger.warn({channel, message}, 'Failed to parse SSO event');
	}
});

// ─── Create Hono app ────────────────────────────────────────────

const app = new Hono();

app.use(
	logger((message: string, ...rest: string[]) => {
		Logger.info(rest.length > 0 ? `${message} ${rest.join(' ')}` : message);
	}),
);

// Global error handler
app.onError((err, ctx) => {
	Logger.error({error: err.message, stack: err.stack}, 'Unhandled SSO server error');
	return ctx.json({error: 'internal_server_error'}, 500);
});

// Mount SSO routes
const ssoRoutes = createSsoRoutes(sessionStore, tokenService);
app.route('/sso', ssoRoutes);
app.route('/', ssoRoutes);

// ─── Start server ───────────────────────────────────────────────

serve({
	fetch: app.fetch,
	hostname: '0.0.0.0',
	port: SsoConfig.port,
});

Logger.info(
	{
		port: SsoConfig.port,
		issuer: SsoConfig.jwt.issuer,
		accessTokenTtl: SsoConfig.jwt.accessTokenTtl,
		refreshTokenTtl: SsoConfig.jwt.refreshTokenTtl,
		sessionTtl: SsoConfig.session.ttl,
		allowedRedirectUris: SsoConfig.allowedRedirectUris,
	},
	`Fluxer SSO server listening on http://0.0.0.0:${SsoConfig.port}`,
);
