// Single source of truth for the scan worker's BullMQ options (issue #17).
// worker/index.ts (prod), benchmark.ts, and worker-e2e.check.ts all build their
// worker through this factory so the benchmark can't silently stop measuring the
// prod configuration (lockDuration/useWorkerThreads/stalledInterval/maxStalledCount).

import { Worker } from 'bullmq';
import { bullRedis } from '../db/bull-redis.js';

const isProd = process.env.NODE_ENV === 'production';
const ext = isProd ? '.js' : '.ts';

export function buildScanWorker(concurrency: number): Worker {
  return new Worker('github-scans', new URL(`./scan-processor${ext}`, import.meta.url).pathname, {
    connection: bullRedis,
    concurrency,
    lockDuration: 600000,
    useWorkerThreads: true,
    stalledInterval: 60000,
    maxStalledCount: 2,
  });
}
