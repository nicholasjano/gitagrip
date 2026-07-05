// round-robin GitHub token distributor for OSSF Scorecard runs.
// a module-level counter would reset to 0 in each worker thread/process and
// make all concurrent workers hammer the same token. Redis INCR gives one
// shared atomic counter across all workers on the same Redis.

import { bullRedis } from '../../db/bull-redis.js';
import type { ScanLogger } from '../logger.js';

const TOKEN_KEY = 'scorecard:token_idx';

// ponytail: split once at import; tokens never change at runtime.
const TOKENS: string[] = (process.env.SCORECARD_GITHUB_TOKENS ?? '')
  .split(',')
  .map((t) => t.trim())
  .filter((t) => t.length > 0);

export function hasScorecardTokens(): boolean {
  return TOKENS.length > 0;
}

// atomically increment the shared counter and pick a token by modulo.
// INCR is safe past 2^53; modulo keeps the index in range.
export async function getNextToken(): Promise<string> {
  const idx = await bullRedis.incr(TOKEN_KEY);
  return TOKENS[(idx - 1) % TOKENS.length]!;
}

// one cheap call per scan so we can log per-token rate-limit remaining and
// warn before Scorecard hits a wall. Scorecard's own JSON output hides this.
export async function logRateLimit(token: string, logger: ScanLogger): Promise<void> {
  try {
    const res = await fetch('https://api.github.com/rate_limit', {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'gitagrip-scorecard',
      },
    });
    if (!res.ok) {
      logger.warn('scorecard', `rate_limit fetch returned ${res.status}`);
      return;
    }
    const body = (await res.json()) as { rate?: { remaining?: number } };
    const remaining = body.rate?.remaining;
    if (typeof remaining !== 'number') return;
    if (remaining < 500) {
      logger.warn('scorecard', `GitHub rate limit low: ${remaining} remaining`);
    } else {
      logger.info('scorecard', `GitHub rate limit: ${remaining} remaining`);
    }
  } catch (err) {
    // rate-limit visibility is best-effort; never block a scan on it
    logger.warn('scorecard', `rate_limit fetch failed: ${(err as Error).message}`);
  }
}
