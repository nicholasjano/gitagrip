// redis connection for the express app (for refresh token storage)

// NOTE: BullMQ workers require a SEPARATE Redis connection with maxRetriesPerRequest: null
// (blocking commands need infinite retries). Do NOT reuse this connection for BullMQ.
// Create a dedicated connection in the worker initialization code.
import { Redis } from 'ioredis';

if (!process.env.REDIS_URL) {
  throw new Error('REDIS_URL environment variable is required');
}

export const redis = new Redis(process.env.REDIS_URL, {
  maxRetriesPerRequest: 3,
});

redis.on('error', (err) => {
  console.error('Redis connection error:', err);
});
