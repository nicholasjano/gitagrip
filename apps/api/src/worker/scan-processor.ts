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

    // phase A (api-bound) + phase B (light tools) run in parallel
    // TODO (issue #15): phaseA — scorecard
    // TODO (issues #13/#14): phaseB — Promise.all([gitleaks, jscpd, lizard])

    const phaseA = async () => {
      // TODO (issue #15): run scorecard
    };

    const phaseB = async () => {
      // TODO (issues #13/#14): Promise.all([gitleaks, jscpd, lizard])
    };

    await Promise.all([phaseA(), phaseB()]);
    if (abortController.signal.aborted) {
      await db
        .update(scans)
        .set({
          status: 'timeout',
          errorMessage: 'Scan exceeded 5 minute timeout',
          updatedAt: sql`NOW()`,
        })
        .where(eq(scans.id, scanId));
      throw new UnrecoverableError('Job timeout after phases A/B');
    }
    await job.updateProgress(60);

    // phase C (heavy, sequential)
    // TODO (issue #13): trivy
    if (abortController.signal.aborted) {
      await db
        .update(scans)
        .set({
          status: 'timeout',
          errorMessage: 'Scan exceeded 5 minute timeout',
          updatedAt: sql`NOW()`,
        })
        .where(eq(scans.id, scanId));
      throw new UnrecoverableError('Job timeout after phase C');
    }
    await job.updateProgress(75);

    // phase D (heaviest, sequential)
    // TODO (issue #13): opengrep
    if (abortController.signal.aborted) {
      await db
        .update(scans)
        .set({
          status: 'timeout',
          errorMessage: 'Scan exceeded 5 minute timeout',
          updatedAt: sql`NOW()`,
        })
        .where(eq(scans.id, scanId));
      throw new UnrecoverableError('Job timeout after phase D');
    }
    await job.updateProgress(80);

    // TODO (issue #16): aggregate CategoryScore[] from all tools, write scan_categories rows

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
