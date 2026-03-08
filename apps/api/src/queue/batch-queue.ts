// identical to scan-queue.ts, but for scan batches
// queue holds parent jobs that coordinate multiple child scan jobs
// child jobs go to scan-queue

import { Queue } from 'bullmq';
import { bullRedis } from '../db/bull-redis.js';

export const batchQueue = new Queue('scan-batches', {
  connection: bullRedis,
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 1000,
    },
    removeOnComplete: {
      age: 86400,
    },
    removeOnFail: {
      age: 604800,
    },
  },
});
