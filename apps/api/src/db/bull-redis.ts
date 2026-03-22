// Dedicated Redis connection for BullMQ workers and queues.
// maxRetriesPerRequest: null is REQUIRED for BullMQ - blocking commands need infinite retries.
import { Redis } from 'ioredis';

if (!process.env.REDIS_URL) {
  throw new Error('REDIS_URL environment variable is required');
}

export const bullRedis = new Redis(process.env.REDIS_URL, {
  maxRetriesPerRequest: null,
});

bullRedis.on('error', (err) => {
  console.error('BullMQ Redis connection error:', err);
});
