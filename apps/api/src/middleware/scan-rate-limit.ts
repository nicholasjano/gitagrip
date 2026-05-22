import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import type { Request } from 'express';
import { RedisStore } from 'rate-limit-redis';
import type { RedisReply } from 'rate-limit-redis';
import { redis } from '../db/redis.js';

const skipInDev = process.env.NODE_ENV !== 'production';
function createRedisStore(prefix: string): RedisStore {
  return new RedisStore({
    prefix,
    sendCommand: (...args: string[]) => {
      const [command, ...rest] = args;
      if (!command) {
        return Promise.reject(new Error('Missing Redis command'));
      }
      return redis.call(command, ...rest) as Promise<RedisReply>;
    },
  });
}

function getLimiterKey(req: Request): string {
  const userId = req.user?.id;
  if (userId) return userId;
  return req.ip ? ipKeyGenerator(req.ip) : 'unknown';
}

// keyed by user ID, not IP — each authenticated user gets their own bucket.
// IP-based limiting would unfairly penalize users on shared networks (VPNs, offices).
export const scanSubmitLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  store: createRedisStore('rate:scan-submit:'),
  skip: () => skipInDev,
  // req.user is set by requireAuth before this limiter runs
  keyGenerator: getLimiterKey,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many scan submissions. Try again in 15 minutes.' },
});

export const batchSubmitLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 2,
  store: createRedisStore('rate:batch-submit:'),
  skip: () => skipInDev,
  keyGenerator: getLimiterKey,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many batch scan submissions. Try again in 15 minutes.' },
});

// status polling is public and expected to be called frequently — IP-based is fine here
export const scanStatusLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  store: createRedisStore('rate:scan-status:'),
  skip: () => skipInDev,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many status requests. Slow down polling.' },
});
