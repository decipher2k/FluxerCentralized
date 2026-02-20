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

import type {ICacheService} from '~/infrastructure/ICacheService';
import {Logger} from '~/Logger';

/**
 * Escalating account lockout thresholds.
 * Each entry defines the number of cumulative failed attempts
 * and the lockout duration (in seconds) that applies once that
 * threshold is reached.  Thresholds are evaluated from highest
 * to lowest, so the first match wins.
 */
const LOCKOUT_TIERS: ReadonlyArray<{readonly failures: number; readonly lockoutSeconds: number}> = [
	{failures: 20, lockoutSeconds: 24 * 60 * 60}, // 20+ failures → 24 h
	{failures: 10, lockoutSeconds: 60 * 60}, // 10+ failures → 1 h
	{failures: 5, lockoutSeconds: 15 * 60}, // 5+ failures  → 15 min
];

/** Maximum TTL for the failure counter in Redis (48 hours). */
const FAILURE_COUNTER_TTL_SECONDS = 48 * 60 * 60;

interface LockoutState {
	/** Cumulative number of failed login attempts. */
	failedAttempts: number;
	/** Unix‑ms timestamp when the current lockout period ends (0 = not locked). */
	lockedUntil: number;
}

/**
 * Provides escalating account lockout to mitigate distributed brute‑force
 * attacks.  Failed login attempts are tracked **per email address** (not
 * per IP), so the protection is effective even when the attacker rotates
 * source addresses.
 *
 * Lockout tiers:
 *  -  5 failures → 15 minutes
 *  - 10 failures →  1 hour
 *  - 20 failures → 24 hours
 *
 * On a successful login the counter is reset.
 */
export class AccountLockoutService {
	constructor(private readonly cacheService: ICacheService) {}

	private cacheKey(email: string): string {
		return `account-lockout:${email.toLowerCase()}`;
	}

	/**
	 * Check whether the account identified by `email` is currently locked.
	 *
	 * @returns An object with `locked: false` when login may proceed, or
	 *          `locked: true` together with `retryAfterSeconds` indicating
	 *          how long the caller must wait.
	 */
	async checkLockout(email: string): Promise<{locked: false} | {locked: true; retryAfterSeconds: number}> {
		const state = await this.cacheService.get<LockoutState>(this.cacheKey(email));
		if (!state) {
			return {locked: false};
		}

		const now = Date.now();
		if (state.lockedUntil > now) {
			const retryAfterSeconds = Math.ceil((state.lockedUntil - now) / 1000);
			return {locked: true, retryAfterSeconds};
		}

		return {locked: false};
	}

	/**
	 * Record a failed login attempt for `email` and—if a lockout threshold
	 * is reached—activate the corresponding lockout period.
	 */
	async recordFailedAttempt(email: string): Promise<void> {
		const key = this.cacheKey(email);
		const existing = await this.cacheService.get<LockoutState>(key);

		const failedAttempts = (existing?.failedAttempts ?? 0) + 1;

		let lockoutSeconds = 0;
		for (const tier of LOCKOUT_TIERS) {
			if (failedAttempts >= tier.failures) {
				lockoutSeconds = tier.lockoutSeconds;
				break;
			}
		}

		const lockedUntil = lockoutSeconds > 0 ? Date.now() + lockoutSeconds * 1000 : 0;

		const newState: LockoutState = {failedAttempts, lockedUntil};
		await this.cacheService.set<LockoutState>(key, newState, FAILURE_COUNTER_TTL_SECONDS);

		if (lockoutSeconds > 0) {
			Logger.warn(
				{email, failedAttempts, lockoutSeconds},
				'Account lockout activated due to repeated failed login attempts',
			);
		}
	}

	/**
	 * Reset the lockout counter for `email` (e.g. after a successful login).
	 */
	async resetLockout(email: string): Promise<void> {
		await this.cacheService.delete(this.cacheKey(email));
	}
}
