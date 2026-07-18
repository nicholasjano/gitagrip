// Scan pipeline extracted from scan-processor.ts (issue #17).
// Owns the single-repo lifecycle: clone → detect → A/B/C/D → blend → score → cleanup.
// It does not PERSIST results (the worker owns DB writes) and it throws on
// abort/failure for the caller to map to status. Note: it is not fully infra-free
// at import time — clone.ts imports `db` (used only on size/disk failure paths)
// and scorecard-tokens.ts imports `bullRedis` (cross-worker token bucket), so
// DATABASE_URL/REDIS_URL must be defined to load it. The happy path issues no DB
// query. One consumer (benchmark) reads timings; the worker ignores them.

import { UnrecoverableError } from 'bullmq';
import { cloneRepo } from './clone.js';
import { detectFiles, type FileManifest } from './detect-files.js';
import { getCategoryApplicability } from './applicability.js';
import { cleanupRepo } from './cleanup.js';
import { killAllToolProcesses } from './run-tool.js';
import { combineCodeQuality } from './scoring/code-quality.js';
import { combineMaintenance } from './scoring/maintenance.js';
import {
  combineCICDDevops,
  combineRepoSecurityPosture,
  combineWorkflowSecurity,
} from './scoring/scorecard-categories.js';
import { computeOverallScore, type ScoringResult } from './scoring/aggregate.js';
import { isTinyRepo, scoreRepositoryOverview } from './scoring/repo-overview.js';
import { runCICDCheck } from './tools/cicd-check.js';
import { runDocsCheck } from './tools/docs-check.js';
import { runGitleaks } from './tools/gitleaks.js';
import { runJscpd } from './tools/jscpd.js';
import { runLizard } from './tools/lizard.js';
import { runScorecard } from './tools/scorecard.js';
import { runTrivy } from './tools/trivy.js';
import { runOpengrep } from './tools/opengrep.js';
import { createScanLogger, type ScanLogger } from './logger.js';
import {
  hasUsableCategoryData,
  notApplicableScore,
  type CategoryScore,
  type PartialToolScore,
} from './types.js';

export interface ScanInput {
  scanId: string;
  repoOwner: string;
  repoName: string;
  defaultBranch: string;
  sizeKb: number;
  isPrivate: boolean;
  pushedAt: Date | null;
  stars: number | null;
  language: string | null;
  isFork: boolean;
  description: string | null;
}

export type PhaseName =
  | 'clone'
  | 'detect'
  | 'phaseA'
  | 'phaseB'
  | 'phaseC'
  | 'phaseD'
  | 'scoring'
  | 'cleanup';
export type ToolName =
  | 'scorecard'
  | 'gitleaks'
  | 'lizard'
  | 'jscpd'
  | 'docsCheck'
  | 'cicdCheck'
  | 'trivy'
  | 'opengrep';

export interface ScanTimings {
  phases: Record<PhaseName, number>;
  tools: Record<ToolName, number>;
}

export interface ScanPipelineResult {
  result: ScoringResult;
  showOnLeaderboard: boolean;
  timings: ScanTimings;
  fileCount: number;
  sizeKb: number;
}

export function emptyTimings(): ScanTimings {
  return {
    phases: {
      clone: 0,
      detect: 0,
      phaseA: 0,
      phaseB: 0,
      phaseC: 0,
      phaseD: 0,
      scoring: 0,
      cleanup: 0,
    },
    tools: {
      scorecard: 0,
      gitleaks: 0,
      lizard: 0,
      jscpd: 0,
      docsCheck: 0,
      cicdCheck: 0,
      trivy: 0,
      opengrep: 0,
    },
  };
}

// canonical key lists (single source for benchmark + temp e2e checks)
export const PHASE_KEYS = Object.keys(emptyTimings().phases) as PhaseName[];
export const TOOL_KEYS = Object.keys(emptyTimings().tools) as ToolName[];

// Scorecard-blended categories vary with live GitHub API state — excluded from
// determinism checks (issue #17). Shared by benchmark.ts + temp e2e checks.
export const SCORECARD_BLENDED = new Set([
  'maintenance_community',
  'cicd_devops',
  'repo_security_posture',
  'workflow_security',
]);

export interface ScanPipelineContext {
  logger?: ScanLogger;
  signal: AbortSignal;
  // optional progress callback mirroring job.updateProgress (worker passes, benchmark omits)
  onProgress?: (pct: number) => void | Promise<void>;
}

export async function runScanPipeline(
  input: ScanInput,
  ctx: ScanPipelineContext,
): Promise<ScanPipelineResult> {
  const {
    scanId,
    repoOwner,
    repoName,
    defaultBranch,
    sizeKb,
    isPrivate,
    pushedAt,
    stars,
    language,
    isFork,
    description,
  } = input;

  const logger = ctx.logger ?? createScanLogger(scanId);
  const timings = emptyTimings();
  let repoDir: string | undefined;

  const toolCtx = {
    repoDir: '',
    scanId,
    logger,
    signal: ctx.signal,
  };

  const markPhase = async <T>(name: PhaseName, fn: () => Promise<T>): Promise<T> => {
    const start = performance.now();
    try {
      return await fn();
    } finally {
      timings.phases[name] = Math.round(performance.now() - start);
    }
  };
  const markTool = async <T>(name: ToolName, fn: () => Promise<T>): Promise<T> => {
    const start = performance.now();
    try {
      return await fn();
    } finally {
      timings.tools[name] = Math.round(performance.now() - start);
    }
  };

  try {
    if (ctx.signal.aborted) throw new UnrecoverableError('Job timeout before starting');

    // clone
    repoDir = await markPhase('clone', () =>
      cloneRepo(repoOwner, repoName, scanId, defaultBranch, sizeKb, ctx.signal),
    );
    toolCtx.repoDir = repoDir;
    if (ctx.signal.aborted) throw new UnrecoverableError('Clone repo timeout');
    await ctx.onProgress?.(15);

    // detect
    const manifest: FileManifest = await markPhase('detect', () => detectFiles(repoDir!));
    if (ctx.signal.aborted) throw new UnrecoverableError('Detect files timeout');
    await ctx.onProgress?.(30);

    const applicability = getCategoryApplicability(manifest);

    // Phase A: Scorecard (API-bound) parallel with Phase B (CPU-bound).
    // Scorecard failure (crash/timeout/parse) -> N/A portions.
    // Rate-limit errors propagate so the worker's BullMQ backoff retries the scan.
    const categoryScores: CategoryScore[] = [];
    let lizardResult: PartialToolScore | undefined;

    const phaseA = async (): Promise<CategoryScore[] | null> => {
      try {
        return await markTool('scorecard', () =>
          runScorecard({
            ...toolCtx,
            scan: { repoOwner, repoName, isPrivate },
          }),
        );
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
      const [gitleaksScores, lizard, jscpdResult, docsScores, cicdScores] = await Promise.all([
        markTool('gitleaks', () => runGitleaks(toolCtx)),
        runQualityTools
          ? markTool('lizard', () => runLizard(toolCtx))
          : Promise.resolve(skippedPartial()),
        runQualityTools
          ? markTool('jscpd', () => runJscpd(toolCtx))
          : Promise.resolve(skippedPartial()),
        markTool('docsCheck', () => runDocsCheck({ ...toolCtx, manifest })),
        markTool('cicdCheck', () => runCICDCheck({ ...toolCtx, manifest, applicability })),
      ]);
      lizardResult = lizard;
      categoryScores.push(...gitleaksScores);
      categoryScores.push(combineCodeQuality(lizard, jscpdResult, applicability.code_quality));
      categoryScores.push(...docsScores, ...cicdScores);
    };

    // Promise.all runs A and B in parallel; each branch's wall time is the
    // phase duration (the slowest branch is the gate). Capture start before
    // invoking so we don't lose the dispatch tick.
    const phaseAStart = performance.now();
    const phaseAPromise = phaseA();
    const phaseBPromise = phaseB();
    const [scorecardScores] = await Promise.all([
      phaseAPromise.then((v) => {
        timings.phases.phaseA = Math.round(performance.now() - phaseAStart);
        return v;
      }),
      phaseBPromise.then((v) => {
        timings.phases.phaseB = Math.round(performance.now() - phaseAStart);
        return v;
      }),
    ]);
    if (ctx.signal.aborted) {
      killAllToolProcesses();
      throw new UnrecoverableError('Job timeout after phases A/B');
    }
    await ctx.onProgress?.(60);

    const trivyScores = await markPhase('phaseC', () =>
      markTool('trivy', () => runTrivy({ ...toolCtx, manifest })),
    );
    categoryScores.push(...trivyScores);
    if (ctx.signal.aborted) {
      killAllToolProcesses();
      throw new UnrecoverableError('Job timeout after phase C');
    }
    await ctx.onProgress?.(75);

    const opengrepScores = await markPhase('phaseD', () =>
      markTool('opengrep', () => runOpengrep({ ...toolCtx, applicability })),
    );
    categoryScores.push(...opengrepScores);
    if (ctx.signal.aborted) {
      killAllToolProcesses();
      throw new UnrecoverableError('Job timeout after phase D');
    }
    await ctx.onProgress?.(80);

    // Blend Scorecard + file/Opengrep/SECURITY.md portions (issue #15).
    const scorecardByCategory = new Map<string, CategoryScore>();
    for (const s of scorecardScores ?? []) {
      scorecardByCategory.set(s.category, s);
    }
    const findScore = (cat: CategoryScore['category']): CategoryScore =>
      categoryScores.find((s) => s.category === cat) ?? notApplicableScore(cat, 'not yet computed');

    const blended: CategoryScore[] = [
      combineMaintenance(
        scorecardByCategory.get('maintenance_community') ?? null,
        pushedAt,
        stars ?? 0,
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
      throw new UnrecoverableError('All security tools failed');
    }

    // Score repository_overview + aggregate (issue #16)
    categoryScores.push(
      scoreRepositoryOverview({
        stars: stars ?? 0,
        sizeKb,
        language,
        isFork,
        description,
      }),
    );

    const result = await markPhase('scoring', async () => computeOverallScore(categoryScores));

    const tiny = isTinyRepo(
      manifest.totalFiles,
      manifest.supportedLanguageFiles,
      lizardResult,
      applicability.code_quality,
    );
    const showOnLeaderboard = result.leaderboardEligible && !tiny;

    await ctx.onProgress?.(100);
    logger.info('scan', 'scan completed', {
      score: result.overallScore,
      categories: result.categories.length,
    });

    return {
      result,
      showOnLeaderboard,
      timings,
      fileCount: manifest.totalFiles,
      sizeKb: manifest.totalSizeKb,
    };
  } finally {
    // cleanup timing captured separately so the benchmark sees real disk-remove cost
    const cleanupStart = performance.now();
    try {
      if (repoDir) await cleanupRepo(repoDir);
    } finally {
      timings.phases.cleanup = Math.round(performance.now() - cleanupStart);
      killAllToolProcesses();
    }
  }
}
