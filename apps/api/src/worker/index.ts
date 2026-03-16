// creates worker instances for the scan and batch processors (separate from express app)

// TODO: add stalledInterval and maxStalledCount config once scan routes are built

import { Worker } from 'bullmq';
import { bullRedis } from '../db/bull-redis.js';
import { db } from '../db/index.js';

// Determine file extension based on environment
const isProd = process.env.NODE_ENV === 'production';
const ext = isProd ? '.js' : '.ts';

// Scan worker
const scanWorker = new Worker(
  'github-scans',
  new URL(`./scan-processor${ext}`, import.meta.url).pathname,
  {
    connection: bullRedis,
    concurrency: 3,
    lockDuration: 300000,
    useWorkerThreads: true,
  },
);

// Batch worker
const batchWorker = new Worker(
  'scan-batches',
  new URL(`./batch-processor${ext}`, import.meta.url).pathname,
  {
    connection: bullRedis,
    concurrency: 3,
    lockDuration: 300000,
    useWorkerThreads: true,
  },
);

// Logging
scanWorker.on('completed', (job) => {
  console.log(`Scan job ${job.id} completed`);
});

scanWorker.on('failed', (job, err) => {
  console.error(`Scan job ${job?.id} failed:`, err.message);
});

batchWorker.on('completed', (job) => {
  console.log(`Batch job ${job.id} completed`);
});

batchWorker.on('failed', (job, err) => {
  console.error(`Batch job ${job?.id} failed:`, err.message);
});

// Graceful shutdown
async function shutdown() {
  console.log('Shutting down workers...');

  const timeout = setTimeout(() => {
    console.error('Forced shutdown after 30s timeout');
    process.exit(1);
  }, 30000);

  try {
    await scanWorker.close();
    await batchWorker.close();
    await bullRedis.quit();
    await db.$client.end();
    clearTimeout(timeout);
    console.log('Workers shut down gracefully');
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

console.log('Workers started');
console.log('Scan worker: concurrency 3, watching github-scans queue');
console.log('Batch worker: concurrency 3, watching scan-batches queue');
