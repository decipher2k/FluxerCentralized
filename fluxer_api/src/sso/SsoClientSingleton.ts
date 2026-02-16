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

import {createHash} from 'node:crypto';
import {Redis} from 'ioredis';
import {Config} from '~/Config';
import {Logger} from '~/Logger';
import {SsoClient} from './SsoClient';

/** Pub/Sub channels — must match the SSO server's GlobalSessionStore channels. */
const SSO_SESSION_INVALIDATED = 'sso:session-invalidated';
const SSO_GLOBAL_LOGOUT = 'sso:global-logout';

let ssoClient: SsoClient | null = null;
let ssoSubscriber: Redis | null = null;
let initialized = false;

/**
 * Callbacks that API services can register to react to SSO events.
 * E.g., the gateway service can disconnect invalidated sessions.
 */
type SessionInvalidatedHandler = (sessionId: string, userId: string) => void;
type GlobalLogoutHandler = (userId: string, sessionIds: string[]) => void;

const sessionInvalidatedHandlers: SessionInvalidatedHandler[] = [];
const globalLogoutHandlers: GlobalLogoutHandler[] = [];

/**
 * Register a callback for when a specific session is invalidated globally.
 */
export function onSsoSessionInvalidated(handler: SessionInvalidatedHandler): void {
	sessionInvalidatedHandlers.push(handler);
}

/**
 * Register a callback for when a user is logged out from all instances.
 */
export function onSsoGlobalLogout(handler: GlobalLogoutHandler): void {
	globalLogoutHandlers.push(handler);
}

/**
 * Get the singleton SSO client instance.
 * Returns null if SSO is not configured.
 */
export function getSsoClient(): SsoClient | null {
	return ssoClient;
}

/**
 * Initialize the SSO client and Redis pub/sub listener if SSO is configured.
 * Called during API server startup.
 */
export async function initializeSsoClient(): Promise<void> {
	if (initialized) return;
	initialized = true;

	if (!Config.sso.enabled || !Config.sso.serverUrl || !Config.sso.serviceSecret) {
		Logger.info('SSO is not configured (SSO_ENABLED not set). Running in standalone mode.');
		return;
	}

	// Generate a stable instance ID based on hostname + port
	const instanceId = `api-${createHash('sha256').update(`${process.env.HOSTNAME || 'localhost'}:${Config.port}`).digest('hex').slice(0, 8)}`;

	ssoClient = new SsoClient(Config.sso.serverUrl, Config.sso.serviceSecret, instanceId);
	await ssoClient.initialize();

	// Subscribe to SSO session events for cross-instance invalidation
	await subscribeSsoEvents();

	Logger.info({ssoServerUrl: Config.sso.serverUrl, instanceId}, 'SSO client initialized');
}

/**
 * Subscribe to SSO pub/sub channels so this API instance reacts
 * to session invalidations from other instances in real-time.
 */
async function subscribeSsoEvents(): Promise<void> {
	try {
		ssoSubscriber = new Redis(Config.redis.url);

		await ssoSubscriber.subscribe(SSO_SESSION_INVALIDATED, SSO_GLOBAL_LOGOUT);

		ssoSubscriber.on('message', (channel: string, message: string) => {
			try {
				const data = JSON.parse(message) as Record<string, unknown>;

				switch (channel) {
					case SSO_SESSION_INVALIDATED: {
						const sessionId = data.sessionId as string;
						const userId = data.userId as string;
						Logger.debug({sessionId, userId}, 'SSO event: session invalidated on another instance');
						for (const handler of sessionInvalidatedHandlers) {
							handler(sessionId, userId);
						}
						break;
					}
					case SSO_GLOBAL_LOGOUT: {
						const userId = data.userId as string;
						const sessionIds = (data.sessionIds as string[]) || [];
						Logger.info({userId, sessionCount: sessionIds.length}, 'SSO event: global logout');
						for (const handler of globalLogoutHandlers) {
							handler(userId, sessionIds);
						}
						break;
					}
				}
			} catch {
				Logger.warn({channel}, 'Failed to parse SSO pub/sub event');
			}
		});

		Logger.info('Subscribed to SSO session invalidation events');
	} catch (error) {
		Logger.error({error}, 'Failed to subscribe to SSO events — cross-instance invalidation will not work');
	}
}
