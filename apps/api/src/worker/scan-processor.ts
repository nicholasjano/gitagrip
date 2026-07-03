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
import { combineCodeQuality } from '../scanner/scoring/code-quality.js';
import { combineMaintenance } from '../scanner/scoring/maintenance.js';
import {
  combineCICDDevops,
  combineRepoSecurityPosture,
  combineWorkflowSecurity,
} from '../scanner/scoring/scorecard-categories.js';
import { runCICDCheck } from '../scanner/tools/cicd-check.js';
import { runDocsCheck } from '../scanner/tools/docs-check.js';
import { runGitleaks } from '../scanner/tools/gitleaks.js';
import { runJscpd } from '../scanner/tools/jscpd.js';
import { runLizard } from '../scanner/tools/lizard.js';
import { runScorecard } from '../scanner/tools/scorecard.js';
import { runTrivy } from '../scanner/tools/trivy.js';
import { runOpengrep } from '../scanner/tools/opengrep.js';
import {
  hasUsableCategoryData,
  notApplicableScore,
  type CategoryScore,
  type PartialToolScore,
} from '../scanner/types.js';

interface ScanJobData {
  scanId: string;
  repoOwner: string;
  repoName: string;
  githubRepoId: number;
  defaultBranch: string;
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

  const categoryScores: CategoryScore[] = [];
  const toolCtx = {
    repoDir: '',
    scanId,
    logger,
    signal: abortController.signal,
  };

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
      .returning({
        id: scans.id,
        isPrivate: scans.isPrivate,
        pushedAt: scans.pushedAt,
        stars: scans.stars,
      });

    if (updateResult.length === 0) {
      // Scan was already processed or cancelled
      logger.info('scan', 'scan already processed or cancelled');
      return;
    }

    const scanRow = updateResult[0]!;

    // Clone repo
    repoDir = await cloneRepo(
      repoOwner,
      repoName,
      scanId,
      defaultBranch,
      sizeKb,
      abortController.signal,
    );
    toolCtx.repoDir = repoDir;
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

    const applicability = getCategoryApplicability(manifest);

    // Phase A: Scorecard (API-bound) runs in parallel with Phase B (CPU-bound).
    // Scorecard failure (crash/timeout/parse) -> degrade to N/A portions.
    // Rate-limit errors propagate so BullMQ backoff retries the whole scan.
    const phaseA = async (): Promise<CategoryScore[] | null> => {
      try {
        return await runScorecard({
          ...toolCtx,
          scan: { repoOwner, repoName, isPrivate: scanRow.isPrivate },
        });
      } catch (err) {
        if (/rate limit/i.test((err as Error).message)) throw err;
        logger.warn('scorecard', `Scorecard failed, degrading: ${(err as Error).message}`);
        return null;
      }
    };

    const skippedPartial = (): PartialToolScore => ({
      score: 0,
      detail: '',
      failed: true,
      failureReason: 'skipped',
    });

    const phaseB = async () => {
      const runQualityTools = applicability.code_quality;
      const [gitleaksScores, lizardResult, jscpdResult, docsScores, cicdScores] = await Promise.all(
        [
          runGitleaks(toolCtx),
          runQualityTools ? runLizard(toolCtx) : Promise.resolve(skippedPartial()),
          runQualityTools ? runJscpd(toolCtx) : Promise.resolve(skippedPartial()),
          runDocsCheck({ ...toolCtx, manifest }),
          runCICDCheck({ ...toolCtx, manifest, applicability }),
        ],
      );
      categoryScores.push(...gitleaksScores);
      categoryScores.push(
        combineCodeQuality(lizardResult, jscpdResult, applicability.code_quality),
      );
      categoryScores.push(...docsScores, ...cicdScores);
    };

    const [scorecardScores] = await Promise.all([phaseA(), phaseB()]);
    if (abortController.signal.aborted) {
      killAllToolProcesses();
      await markScanTimeout(scanId);
      throw new UnrecoverableError('Job timeout after phases A/B');
    }
    await job.updateProgress(60);

    const trivyScores = await runTrivy({ ...toolCtx, manifest });
    categoryScores.push(...trivyScores);
    if (abortController.signal.aborted) {
      killAllToolProcesses();
      await markScanTimeout(scanId);
      throw new UnrecoverableError('Job timeout after phase C');
    }
    await job.updateProgress(75);

    const opengrepScores = await runOpengrep({ ...toolCtx, applicability });
    categoryScores.push(...opengrepScores);
    if (abortController.signal.aborted) {
      killAllToolProcesses();
      await markScanTimeout(scanId);
      throw new UnrecoverableError('Job timeout after phase D');
    }
    await job.updateProgress(80);

    // Blend Scorecard + file/Opengrep/SECURITY.md portions (issue #15).
    // Replace the raw tool scores for the 4 Scorecard-fed categories with
    // the enriched combined scores; other categories pass through untouched.
    const scorecardByCategory = new Map<string, CategoryScore>();
    for (const s of scorecardScores ?? []) {
      scorecardByCategory.set(s.category, s);
    }
    const findScore = (cat: CategoryScore['category']): CategoryScore =>
      categoryScores.find((s) => s.category === cat) ?? notApplicableScore(cat, 'not yet computed');

    const blended: CategoryScore[] = [
      combineMaintenance(
        scorecardByCategory.get('maintenance_community') ?? null,
        scanRow.pushedAt,
        scanRow.stars,
      ),
      combineCICDDevops(
        scorecardByCategory.get('cicd_devops') ?? null,
        findScore('cicd_devops'),
        applicability.cicd_devops,
      ),
      combineRepoSecurityPosture(
        scorecardByCategory.get('repo_security_posture') ?? null,
        manifest.hasSecurityPolicy,
      ),
      combineWorkflowSecurity(
        scorecardByCategory.get('workflow_security') ?? null,
        findScore('workflow_security'),
        applicability.workflow_security,
      ),
    ];

    const blendedCategories = new Set(blended.map((s) => s.category));
    const nonBlended = categoryScores.filter((s) => !blendedCategories.has(s.category));
    categoryScores.length = 0;
    categoryScores.push(...nonBlended, ...blended);

    if (!hasUsableCategoryData(categoryScores)) {
      await db
        .update(scans)
        .set({
          status: 'failed',
          errorMessage: 'All security tools failed',
          updatedAt: sql`NOW()`,
        })
        .where(eq(scans.id, scanId));
      throw new UnrecoverableError('All security tools failed');
    }

    // TODO (issue #16): aggregate CategoryScore[] from all tools, write scan_categories rows
    logger.info('scan', 'category scores collected', {
      categoryCount: categoryScores.length,
    });

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
