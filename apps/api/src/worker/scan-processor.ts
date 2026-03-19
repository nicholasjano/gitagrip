// contains code for the scan processor worker
// this worker is responsible for processing a single scan

// TODO: replace sleep + random scores with real scan tools (opengrep, trivy, gitleaks etc) - see scanning tools issue
// githubRepoId unused in mock - will be needed by real scan tools

import type { Job } from 'bullmq';
import { UnrecoverableError } from 'bullmq';
import { eq, sql } from 'drizzle-orm';
import { db } from '../db/index.ts';
import { scans, scanCategories, SCAN_CATEGORY_NAMES } from '../db/schema.ts';

interface ScanJobData {
  scanId: string;
  repoOwner: string;
  repoName: string;
  githubRepoId: number;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

export default async function scanProcessor(job: Job<ScanJobData>) {
  const { scanId, repoOwner, repoName } = job.data;
  // ** job.data also contains githubRepoId (unused in mock, needed by real scan tools) **
  // add back once scan routes are built
  console.log(`Processing scan ${scanId} for ${repoOwner}/${repoName}`);

  // Timeout handling
  const abortController = new AbortController();
  const timeoutId = setTimeout(
    () => {
      abortController.abort();
    },
    5 * 60 * 1000,
  ); // 5 minutes

  try {
    // Check for abort
    if (abortController.signal.aborted) {
      throw new UnrecoverableError('Job timeout before starting');
    }

    // Update status to in_progress (with compare-and-swap guard)
    const updateResult = await db
      .update(scans)
      .set({
        status: 'in_progress',
        updatedAt: sql`NOW()`,
      })
      .where(sql`${scans.id} = ${scanId} AND ${scans.status} = 'queued'`)
      .returning({ id: scans.id });

    if (updateResult.length === 0) {
      // Scan was already processed or cancelled
      console.log(`Scan ${scanId} already processed or cancelled`);
      return;
    }

    // Simulate scan duration (2-5 seconds)
    // TODO: replace with actual scan duration
    const scanDuration = randomInt(2000, 5000);
    await sleep(scanDuration);

    // Check for abort after sleep
    if (abortController.signal.aborted) {
      await db
        .update(scans)
        .set({
          status: 'timeout',
          errorMessage: 'Scan exceeded 5 minute timeout',
          updatedAt: sql`NOW()`,
        })
        .where(eq(scans.id, scanId));
      throw new UnrecoverableError('Job timeout during processing');
    }

    // Generate mock scores
    const overallScore = randomInt(40, 95);
    const categoryScores = SCAN_CATEGORY_NAMES.map((category) => ({
      scanId,
      category,
      score: randomInt(30, 100),
      message: `Mock scan result for ${category}`,
    }));

    // Insert category scores
    await db.insert(scanCategories).values(categoryScores);

    // Update scan to completed
    await db
      .update(scans)
      .set({
        status: 'completed',
        score: overallScore,
        completedAt: sql`NOW()`,
        updatedAt: sql`NOW()`,
      })
      .where(eq(scans.id, scanId));

    console.log(`Scan ${scanId} completed with score ${overallScore}`);
  } catch (err) {
    // Don't update status if it's an UnrecoverableError (already handled)
    if (err instanceof UnrecoverableError) {
      throw err;
    }

    // Update scan to failed
    const errorMessage = err instanceof Error ? err.message : 'Unknown error';
    await db
      .update(scans)
      .set({
        status: 'failed',
        errorMessage,
        updatedAt: sql`NOW()`,
      })
      .where(eq(scans.id, scanId));

    console.error(`Scan ${scanId} failed:`, errorMessage);
    throw err; // Re-throw so BullMQ can retry
  } finally {
    clearTimeout(timeoutId);
  }
}
