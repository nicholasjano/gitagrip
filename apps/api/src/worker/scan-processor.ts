// contains code for the scan processor worker
// thin adapter: owns BullMQ + DB concerns, delegates the scan lifecycle to
// runScanPipeline (issue #17) so the benchmark can drive the same pipeline.

import type { Job } from 'bullmq';
import { UnrecoverableError } from 'bullmq';
import { eq, sql } from 'drizzle-orm';
import { db } from '../db/index.js';
import { scanCategories, scans } from '../db/schema.js';
import { createScanLogger } from '../scanner/logger.js';
import { runScanPipeline, type ScanPipelineResult, type ScanTimings } from '../scanner/run-scan.js';

interface ScanJobData {
  scanId: string;
  repoOwner: string;
  repoName: string;
  githubRepoId: number;
  defaultBranch: string;
  sizeKb: number;
}

export interface ScanProcessorReturnValue {
  timings: ScanTimings;
  score: number;
  applicableCount: number;
  fileCount: number;
  sizeKb: number;
}

async function markScanTimeout(scanId: string): Promise<void> {
  await db
    .update(scans)
    .set({
      status: 'timeout',
      errorMessage: 'Scan exceeded 5 minute timeout',
      updatedAt: sql`NOW()`,
    })
    .where(eq(scans.id, scanId));
}

export default async function scanProcessor(
  job: Job<ScanJobData>,
): Promise<ScanProcessorReturnValue | void> {
  const { scanId, repoOwner, repoName, defaultBranch, sizeKb } = job.data;

  const logger = createScanLogger(scanId);

  logger.info('scan', `processing scan for ${repoOwner}/${repoName}`);

  const abortController = new AbortController();
  const timeoutId = setTimeout(() => abortController.abort(), 5 * 60 * 1000);

  try {
    if (abortController.signal.aborted) {
      throw new UnrecoverableError('Job timeout before starting');
    }

    // CAS into in_progress + read the metadata the pipeline needs
    const updateResult = await db
      .update(scans)
      .set({
        status: 'in_progress',
        updatedAt: sql`NOW()`,
      })
      .where(sql`${scans.id} = ${scanId} AND ${scans.status} = 'queued'`)
      .returning({
        id: scans.id,
        isPrivate: scans.isPrivate,
        pushedAt: scans.pushedAt,
        stars: scans.stars,
        language: scans.language,
        isFork: scans.isFork,
        description: scans.description,
      });

    if (updateResult.length === 0) {
      logger.info('scan', 'scan already processed or cancelled');
      return;
    }

    const scanRow = updateResult[0]!;

    const pipelineResult: ScanPipelineResult = await runScanPipeline(
      {
        scanId,
        repoOwner,
        repoName,
        defaultBranch,
        sizeKb,
        isPrivate: scanRow.isPrivate,
        pushedAt: scanRow.pushedAt,
        stars: scanRow.stars,
        language: scanRow.language,
        isFork: scanRow.isFork,
        description: scanRow.description,
      },
      {
        logger,
        signal: abortController.signal,
        onProgress: (pct) => job.updateProgress(pct),
      },
    );

    const { result, showOnLeaderboard, timings, fileCount, sizeKb: scannedSizeKb } = pipelineResult;

    await db.insert(scanCategories).values(
      result.categories.map((c) => ({
        scanId,
        category: c.category,
        score: String(c.score),
        message: c.message,
        applicable: c.applicable,
      })),
    );

    await db
      .update(scans)
      .set({
        status: 'completed',
        score: result.overallScore,
        showOnLeaderboard,
        completedAt: sql`NOW()`,
        updatedAt: sql`NOW()`,
      })
      .where(eq(scans.id, scanId));

    return {
      timings,
      score: result.overallScore,
      applicableCount: result.applicableCount,
      fileCount,
      sizeKb: scannedSizeKb,
    };
  } catch (err) {
    if (err instanceof UnrecoverableError) {
      // Abort -> timeout. Any other unrecoverable failure (e.g. "All security
      // tools failed") -> failed. clone.ts's write-then-throw cases re-write the
      // same status/message here — an idempotent no-op, simpler than a flag.
      if (abortController.signal.aborted) {
        await markScanTimeout(scanId);
      } else {
        await db
          .update(scans)
          .set({ status: 'failed', errorMessage: err.message, updatedAt: sql`NOW()` })
          .where(eq(scans.id, scanId));
      }
      throw err;
    }

    const errorMessage = err instanceof Error ? err.message : 'Unknown error';
    await db
      .update(scans)
      .set({
        status: 'failed',
        errorMessage,
        updatedAt: sql`NOW()`,
      })
      .where(eq(scans.id, scanId));

    logger.error('scan', 'scan failed', { errorMessage });
    throw err;
  } finally {
    clearTimeout(timeoutId);
  }
}
