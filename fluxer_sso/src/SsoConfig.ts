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

import process from 'node:process';

interface SsoConfig {
	port: number;
	nodeEnv: 'development' | 'production';

	redis: {
		url: string;
	};

	cassandra: {
		hosts: string;
		keyspace: string;
		localDc: string;
		username: string;
		password: string;
	};

	jwt: {
		/** RSA private key PEM for signing SSO tokens */
		privateKey: string;
		/** RSA public key PEM for verifying SSO tokens */
		publicKey: string;
		/** Issuer claim */
		issuer: string;
		/** Access token lifetime in seconds */
		accessTokenTtl: number;
		/** Refresh token lifetime in seconds */
		refreshTokenTtl: number;
	};

	session: {
		/** Global session TTL in seconds (default: 30 days) */
		ttl: number;
		/** How often to refresh "last active" in seconds */
		activityUpdateInterval: number;
	};

	/** Allowed redirect URIs for PKCE auth code flow */
	allowedRedirectUris: string[];

	/** Shared secret for inter-service communication (API → SSO) */
	serviceSecret: string;

	cookie: {
		domain: string;
		secure: boolean;
	};

	endpoints: {
		sso: string;
		api: string;
		app: string;
	};
}

function required(key: string): string {
	const value = process.env[key];
	if (!value) {
		throw new Error(`Missing required environment variable: ${key}`);
	}
	return value;
}

function optional(key: string): string | undefined {
	return process.env[key] || undefined;
}

function optionalInt(key: string, defaultValue: number): number {
	const value = process.env[key];
	if (!value) return defaultValue;
	const parsed = Number.parseInt(value, 10);
	return Number.isNaN(parsed) ? defaultValue : parsed;
}

function optionalBool(key: string, defaultValue = false): boolean {
	const value = process.env[key];
	if (!value) return defaultValue;
	return value.toLowerCase() === 'true' || value === '1';
}

function parseCommaSeparated(value: string): string[] {
	return value
		.split(',')
		.map((item) => item.trim())
		.filter((item) => item.length > 0);
}

function loadSsoConfig(): SsoConfig {
	const ssoEndpoint = required('SSO_ENDPOINT');
	const apiEndpoint = required('FLUXER_API_PUBLIC_ENDPOINT');
	const appEndpoint = required('FLUXER_APP_ENDPOINT');

	const allowedRedirects = optional('SSO_ALLOWED_REDIRECT_URIS');

	return {
		port: optionalInt('SSO_PORT', 8090),
		nodeEnv: (optional('NODE_ENV') as 'development' | 'production') || 'development',

		redis: {
			url: required('REDIS_URL'),
		},

		cassandra: {
			hosts: required('CASSANDRA_HOSTS'),
			keyspace: required('CASSANDRA_KEYSPACE'),
			localDc: optional('CASSANDRA_LOCAL_DC') || 'datacenter1',
			username: required('CASSANDRA_USERNAME'),
			password: required('CASSANDRA_PASSWORD'),
		},

		jwt: {
			privateKey: required('SSO_JWT_PRIVATE_KEY'),
			publicKey: required('SSO_JWT_PUBLIC_KEY'),
			issuer: optional('SSO_JWT_ISSUER') || 'fluxer-sso',
			accessTokenTtl: optionalInt('SSO_ACCESS_TOKEN_TTL', 900), // 15 minutes
			refreshTokenTtl: optionalInt('SSO_REFRESH_TOKEN_TTL', 2592000), // 30 days
		},

		session: {
			ttl: optionalInt('SSO_SESSION_TTL', 2592000), // 30 days
			activityUpdateInterval: optionalInt('SSO_ACTIVITY_UPDATE_INTERVAL', 300), // 5 minutes
		},

		allowedRedirectUris: allowedRedirects
			? parseCommaSeparated(allowedRedirects)
			: [`${apiEndpoint}/sso/callback`, `${appEndpoint}/sso/callback`],

		serviceSecret: required('SSO_SERVICE_SECRET'),

		cookie: {
			domain: optional('SSO_COOKIE_DOMAIN') || '',
			secure: optionalBool('SSO_COOKIE_SECURE', true),
		},

		endpoints: {
			sso: ssoEndpoint,
			api: apiEndpoint,
			app: appEndpoint,
		},
	};
}

export const SsoConfig = loadSsoConfig();
export type {SsoConfig};
