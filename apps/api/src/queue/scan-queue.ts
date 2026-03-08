// individual repo scan job queue

import { Queue } from 'bullmq';
import { bullRedis } from '../db/bull-redis';

export const scanQueue = new Queue('github-scans', {
  connection: bullRedis,
  defaultJobOptions: {
    attempts: 3, // not the same as maxRetriesPerRequest, this is the number of times the job will be retried
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
