// contains code for the scan processor worker
// this worker is responsible for processing a single scan

import type { Job } from 'bullmq';
import { UnrecoverableError } from 'bullmq';
import { eq, sql } from 'drizzle-orm';
import { db } from '../db/index.js';
import { scans } from '../db/schema.js';
import { createScanLogger } from '../scanner/logger.js';
import { cloneRepo } from '../scanner/clone.js';
import { detectFiles } from '../scanner/detect-files.js';
import { getCategoryApplicability } from '../scanner/applicability.js';
import { cleanupRepo } from '../scanner/cleanup.js';
import { killAllToolProcesses } from '../scanner/run-tool.js';

interface ScanJobData {
  scanId: string;
  repoOwner: string;
  repoName: string;
  githubRepoId: number;
  defaultBranch: string;
  sizeKb: number;
}

export default async function scanProcessor(job: Job<ScanJobData>) {
  const { scanId, repoOwner, repoName, defaultBranch, sizeKb } = job.data;

  const logger = createScanLogger(scanId);

  let repoDir: string | undefined;

  logger.info('scan', `processing scan for ${repoOwner}/${repoName}`);

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
      logger.info('scan', 'scan already processed or cancelled');
      return;
    }

    // Clone repo
    repoDir = await cloneRepo(repoOwner, repoName, scanId, defaultBranch, sizeKb);
    if (abortController.signal.aborted) {
      throw new UnrecoverableError('Clone repo timeout');
    }
    await job.updateProgress(15);

    // Detect files
    const manifest = await detectFiles(repoDir);
    if (abortController.signal.aborted) {
      throw new UnrecoverableError('Detect files timeout');
    }
    await job.updateProgress(30);

    // Get category applicability
    // TODO result gets used in future issues
    getCategoryApplicability(manifest);

    // TODO (issue #13): run security tools (gitleaks, trivy, opengrep) in phases A-D
    // each tool calls runTool() from run-tool.ts and returns CategoryScore[]

    // TODO (issue #14): run quality tools (lizard, jscpd) + file-based checks

    // TODO (issue #15): run OSSF scorecard

    // TODO (issue #16): aggregate CategoryScore[] from all tools into per-category
    // scores, write scan_categories rows, compute overall score

    // NOTE: abort check should be in between each tool phase, not after all tools have run
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

    await job.updateProgress(80);

    // Update scan to completed
    await db
      .update(scans)
      .set({
        status: 'completed',
        score: null,
        completedAt: sql`NOW()`,
        updatedAt: sql`NOW()`,
      })
      .where(eq(scans.id, scanId));

    await job.updateProgress(100);
    logger.info('scan', 'scan completed');
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

    logger.error('scan', 'scan failed', { errorMessage });
    throw err; // Re-throw so BullMQ can retry
  } finally {
    clearTimeout(timeoutId);
    if (repoDir) {
      await cleanupRepo(repoDir);
    }

    killAllToolProcesses();
  }
}
