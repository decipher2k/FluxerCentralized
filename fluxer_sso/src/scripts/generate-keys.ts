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

/**
 * Generate RSA-2048 key pair for SSO JWT signing.
 * Run: npx tsx src/scripts/generate-keys.ts
 *
 * Output the keys in PEM format for use in environment variables.
 */

import crypto from 'node:crypto';
import {promisify} from 'node:util';

const generateKeyPair = promisify(crypto.generateKeyPair);

async function main() {
	console.log('Generating RSA-2048 key pair for Fluxer SSO...\n');

	const {publicKey, privateKey} = await generateKeyPair('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: {type: 'spki', format: 'pem'},
		privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
	});

	// Generate a random service secret
	const serviceSecret = crypto.randomBytes(48).toString('base64url');

	console.log('=== SSO_JWT_PRIVATE_KEY ===');
	console.log(privateKey);

	console.log('=== SSO_JWT_PUBLIC_KEY ===');
	console.log(publicKey);

	console.log('=== SSO_SERVICE_SECRET ===');
	console.log(serviceSecret);

	console.log('\n--- Environment Variables (single-line, for .env file) ---\n');

	// Escape newlines for .env file
	const privateKeyOneLine = privateKey.trim().replace(/\n/g, '\\n');
	const publicKeyOneLine = publicKey.trim().replace(/\n/g, '\\n');

	console.log(`SSO_JWT_PRIVATE_KEY="${privateKeyOneLine}"`);
	console.log();
	console.log(`SSO_JWT_PUBLIC_KEY="${publicKeyOneLine}"`);
	console.log();
	console.log(`SSO_SERVICE_SECRET="${serviceSecret}"`);
}

main().catch(console.error);
