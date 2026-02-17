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
import {Logger} from './Logger.js';

export interface SsoAccessTokenPayload {
	/** Subject — Fluxer user ID */
	sub: string;
	/** Global SSO session ID */
	sid: string;
	/** Token type: 'access' */
	type: 'access';
	/** Scope (space-separated) */
	scope: string;
	/** Issued at */
	iat: number;
	/** Expiration */
	exp: number;
	/** Issuer */
	iss: string;
}

export interface SsoRefreshTokenPayload {
	/** Subject — Fluxer user ID */
	sub: string;
	/** Global SSO session ID */
	sid: string;
	/** Token type: 'refresh' */
	type: 'refresh';
	/** Unique token ID for rotation tracking */
	jti: string;
}

export class SsoTokenService {
	private privateKey!: jose.CryptoKey;
	private publicKey!: jose.CryptoKey;

	constructor(
		private privateKeyPem: string,
		private publicKeyPem: string,
		private issuer: string,
		private accessTokenTtl: number,
		private refreshTokenTtl: number,
	) {}

	async initialize(): Promise<void> {
		this.privateKey = await jose.importPKCS8(this.privateKeyPem, 'RS256');
		this.publicKey = await jose.importSPKI(this.publicKeyPem, 'RS256');
		Logger.info('SSO token service initialized with RS256 keys');
	}

	/**
	 * Issue an SSO access token (short-lived JWT).
	 * Any API instance can verify this using the public key without contacting the SSO server.
	 */
	async issueAccessToken(params: {
		userId: string;
		sessionId: string;
		scope?: string;
	}): Promise<string> {
		const now = Math.floor(Date.now() / 1000);

		return new jose.SignJWT({
			sub: params.userId,
			sid: params.sessionId,
			type: 'access',
			scope: params.scope || 'identify',
		})
			.setProtectedHeader({alg: 'RS256', typ: 'JWT'})
			.setIssuedAt(now)
			.setExpirationTime(now + this.accessTokenTtl)
			.setIssuer(this.issuer)
			.setJti(crypto.randomUUID())
			.sign(this.privateKey);
	}

	/**
	 * Issue an SSO refresh token (long-lived JWT).
	 * Used to obtain new access tokens without re-authentication.
	 */
	async issueRefreshToken(params: {
		userId: string;
		sessionId: string;
	}): Promise<string> {
		const jti = crypto.randomUUID();
		const now = Math.floor(Date.now() / 1000);

		return new jose.SignJWT({
			sub: params.userId,
			sid: params.sessionId,
			type: 'refresh',
			jti,
		})
			.setProtectedHeader({alg: 'RS256', typ: 'JWT'})
			.setIssuedAt(now)
			.setExpirationTime(now + this.refreshTokenTtl)
			.setIssuer(this.issuer)
			.sign(this.privateKey);
	}

	/**
	 * Verify and decode an SSO access token.
	 * This can be done by ANY service that has the public key — no SSO server round-trip needed.
	 */
	async verifyAccessToken(token: string): Promise<SsoAccessTokenPayload | null> {
		try {
			const {payload} = await jose.jwtVerify(token, this.publicKey, {
				issuer: this.issuer,
				algorithms: ['RS256'],
			});

			if (payload['type'] !== 'access') return null;

			return payload as unknown as SsoAccessTokenPayload;
		} catch (error) {
			Logger.debug({error}, 'Failed to verify SSO access token');
			return null;
		}
	}

	/**
	 * Verify and decode an SSO refresh token.
	 */
	async verifyRefreshToken(token: string): Promise<SsoRefreshTokenPayload | null> {
		try {
			const {payload} = await jose.jwtVerify(token, this.publicKey, {
				issuer: this.issuer,
				algorithms: ['RS256'],
			});

			if (payload['type'] !== 'refresh') return null;

			return payload as unknown as SsoRefreshTokenPayload;
		} catch (error) {
			Logger.debug({error}, 'Failed to verify SSO refresh token');
			return null;
		}
	}

	/**
	 * Export the public key as JWK for the JWKS endpoint.
	 * API instances fetch this to verify tokens locally.
	 */
	async exportPublicKeyJwk(): Promise<jose.JWK> {
		return jose.exportJWK(this.publicKey);
	}

	/**
	 * Get the public key PEM for distribution to API instances.
	 */
	getPublicKeyPem(): string {
		return this.publicKeyPem;
	}
}
