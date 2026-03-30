// creates worker instances for the scan and batch processors (separate from express app)

import fs from 'fs/promises';
import { Worker, Job } from 'bullmq';
import { eq, sql } from 'drizzle-orm';
import { bullRedis } from '../db/bull-redis.js';
import { db } from '../db/index.js';
import { scans, scanBatches } from '../db/schema.js';
import { scanQueue } from '../queue/scan-queue.js';
import { cleanupRepo } from '../scanner/cleanup.js';

// determine file extension based on environment
const isProd = process.env.NODE_ENV === 'production';
const ext = isProd ? '.js' : '.ts';
const SCAN_DIR_NAME_PREFIX = 'gitagrip-scan-';

// scan /tmp/ for any dirs left by previously crashed workers
async function cleanupStaleTempScanDirs(): Promise<void> {
  const entries = await fs.readdir('/tmp', { withFileTypes: true });
  const staleDirs = entries
    .filter((entry) => entry.isDirectory() && entry.name.startsWith(SCAN_DIR_NAME_PREFIX))
    .map((entry) => `/tmp/${entry.name}`);

  await Promise.all(staleDirs.map((dirPath) => cleanupRepo(dirPath)));

  if (staleDirs.length > 0) {
    console.log(
      `[worker] cleaned ${staleDirs.length} stale temp scan director${staleDirs.length === 1 ? 'y' : 'ies'}`,
    );
  }
}

await cleanupStaleTempScanDirs();

// Scan worker
const scanWorker = new Worker(
  'github-scans',
  new URL(`./scan-processor${ext}`, import.meta.url).pathname,
  {
    connection: bullRedis,
    concurrency: 3,
    lockDuration: 300000,
    useWorkerThreads: true,
    stalledInterval: 60000,
    maxStalledCount: 2,
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
    stalledInterval: 60000,
    maxStalledCount: 2,
  },
);

// Logging + side effects
scanWorker.on('completed', async (job) => {
  console.log(`Scan job ${job.id} completed`);
  // increment batch progress counter if this scan belongs to a batch
  try {
    const [scan] = await db
      .select({ batchId: scans.batchId })
      .from(scans)
      .where(eq(scans.id, job.data.scanId))
      .limit(1);
    if (scan?.batchId) {
      await db
        .update(scanBatches)
        .set({ completedRepos: sql`${scanBatches.completedRepos} + 1`, updatedAt: sql`NOW()` })
        .where(eq(scanBatches.id, scan.batchId));
    }
  } catch (err) {
    console.error(`Failed to increment completed_repos for scan job ${job.id}:`, err);
  }
});

scanWorker.on('failed', (job, err) => {
  console.error(`Scan job ${job?.id} failed:`, err.message);
});

scanWorker.on('stalled', async (jobId) => {
  console.warn(`Scan job ${jobId} stalled`);
  try {
    const job = await Job.fromId(scanQueue, jobId);
    if (!job?.data?.scanId) return;
    await db
      .update(scans)
      .set({ status: 'failed', errorMessage: 'Job stalled', updatedAt: sql`NOW()` })
      .where(
        sql`${scans.id} = ${job.data.scanId} AND ${scans.status} IN ('queued', 'in_progress')`,
      );
  } catch (err) {
    console.error(`Failed to update stalled scan job ${jobId}:`, err);
  }
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
