// TEMPORARY test (issue #17) — PRODUCTION PATH end-to-end through BullMQ + DB.
// Seeds a scan row, enqueues it, runs the real scan-processor in a worker thread
// (useWorkerThreads: true, like prod), then asserts (a) the job return value
// carries per-phase/per-tool timings + score, and (b) the DB rows are persisted.
// This covers the thin worker adapter + DB persistence that runScanPipeline
// itself doesn't touch.
//
// Requires Postgres + Redis + the scan tool binaries. Run on the CX53 / worker
// Docker image with env:
//   pnpm --filter @gitagrip/api exec tsx --env-file=../../.env scripts/worker-e2e.check.ts [owner/repo] [branch]
//
// Delete once #17 ships.

import assert from 'node:assert/strict';
import { randomInt } from 'node:crypto';
import { type Worker, Queue, QueueEvents } from 'bullmq';
import { eq } from 'drizzle-orm';
import { db } from '../src/db/index.js';
import { scans, scanCategories } from '../src/db/schema.js';
import { bullRedis } from '../src/db/bull-redis.js';
import { buildScanWorker } from '../src/worker/build-scan-worker.js';
import { PHASE_KEYS, TOOL_KEYS } from '../src/scanner/run-scan.js';
import type { ScanProcessorReturnValue } from '../src/worker/scan-processor.js';

const [, , repoArg, branchArg] = process.argv;
const REPO = repoArg ?? 'sindresorhus/slugify';
const BRANCH = branchArg ?? 'main';
const [OWNER, NAME] = REPO.split('/');

// mirrors worker/index.ts (prod settings) via the shared factory
function buildWorker(concurrency: number): Worker {
  return buildScanWorker(concurrency);
}

async function main(): Promise<void> {
  const queue = new Queue('github-scans', { connection: bullRedis });
  const queueEvents = new QueueEvents('github-scans', { connection: bullRedis });
  const worker = buildWorker(1);
  let scanId: string | undefined;

  try {
    await queueEvents.waitUntilReady();

    // random githubRepoId avoids the one-active-scan-per-repo unique index
    const githubRepoId = randomInt(1_000_000_000, 2_000_000_000);
    const [row] = await db
      .insert(scans)
      .values({
        githubRepoId,
        repoOwner: OWNER!,
        repoName: NAME!,
        isPrivate: false,
        isFork: false,
        defaultBranch: BRANCH,
        language: 'JavaScript',
        description: 'worker e2e fixture',
        stars: 100,
        sizeKb: 500,
        pushedAt: new Date('2025-01-01T00:00:00Z'),
        status: 'queued',
      })
      .returning({ id: scans.id });
    scanId = row!.id;
    process.stderr.write(`[worker-e2e] seeded scan ${scanId} for ${REPO}@${BRANCH}\n`);

    const job = await queue.add(
      'scan-repo',
      {
        scanId,
        repoOwner: OWNER,
        repoName: NAME,
        githubRepoId,
        defaultBranch: BRANCH,
        sizeKb: 500,
      },
      { jobId: scanId },
    );

    let rv: ScanProcessorReturnValue;
    try {
      rv = (await job.waitUntilFinished(queueEvents, 10 * 60 * 1000)) as ScanProcessorReturnValue;
    } catch (e) {
      const [r] = await db
        .select({ status: scans.status, errorMessage: scans.errorMessage })
        .from(scans)
        .where(eq(scans.id, scanId));
      throw new Error(
        `job did not complete: ${(e as Error).message} (db status=${r?.status}, errorMessage=${r?.errorMessage})`,
        { cause: e },
      );
    }

    // ── return value: timings + score plumbed back through job.returnvalue ─────
    assert.ok(rv, 'processor returned a value');
    for (const k of PHASE_KEYS)
      assert.ok(k in rv.timings.phases, `returnvalue timings.phases has ${k}`);
    for (const k of TOOL_KEYS)
      assert.ok(k in rv.timings.tools, `returnvalue timings.tools has ${k}`);
    assert.equal(typeof rv.score, 'number', 'returnvalue score is a number');
    assert.ok(rv.applicableCount >= 1, 'returnvalue applicableCount >= 1');
    assert.ok(rv.fileCount > 0, 'returnvalue fileCount > 0');
    assert.ok(rv.timings.tools.trivy > 0, 'returnvalue trivy timed');

    // ── DB persistence: the adapter's job ──────────────────────────────────────
    const [scanRow] = await db
      .select({ status: scans.status, score: scans.score })
      .from(scans)
      .where(eq(scans.id, scanId));
    assert.equal(scanRow!.status, 'completed', 'scan row marked completed');
    assert.notEqual(scanRow!.score, null, 'scan row has an overall score');

    const cats = await db
      .select({ category: scanCategories.category })
      .from(scanCategories)
      .where(eq(scanCategories.scanId, scanId));
    assert.ok(cats.length > 0, 'scan_categories rows persisted');

    process.stderr.write(
      `[worker-e2e] completed: score=${scanRow!.score}, ${cats.length} categories, trivy=${rv.timings.tools.trivy}ms\n`,
    );
    console.log('worker-e2e.check: all assertions passed');
  } finally {
    // remove the fixture scan (cascades to scan_categories)
    if (scanId)
      await db
        .delete(scans)
        .where(eq(scans.id, scanId))
        .catch(() => {});
    await worker.close().catch(() => {});
    await queue.close().catch(() => {});
    await queueEvents.close().catch(() => {});
    await bullRedis.quit().catch(() => {});
    await db.$client.end().catch(() => {});
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    process.stderr.write(`\nworker-e2e.check FAILED: ${(err as Error).message}\n`);
    process.exit(1);
  });
