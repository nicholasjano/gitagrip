// TEMPORARY test (issue #17) — FULL SCAN PIPELINE end-to-end.
// Runs the real runScanPipeline (clone → detect → A/B/C/D → blend → score →
// cleanup) against one tiny repo, asserts the result + timing shape, then runs
// it a SECOND time and checks scoring determinism on the non-Scorecard subset.
//
// Requires the scan tool binaries (git, trivy, opengrep, gitleaks, jscpd, lizard)
// + network. NOTE: runScanPipeline is not fully infra-free at import time —
// clone.ts imports `db` and scorecard-tokens.ts imports `bullRedis`, so
// DATABASE_URL + REDIS_URL must be DEFINED (hence --env-file). A live DB is not
// needed on the happy path (clone.ts only writes to the DB on size/disk failure);
// Redis is optional (Scorecard just degrades to N/A without it).
//
// Run on the CX53 or inside the worker Docker image:
//   pnpm --filter @gitagrip/api exec tsx --env-file=../../.env scripts/pipeline-e2e.check.ts [owner/repo] [branch]
//
// Default repo is a tiny one so the run is quick. Delete once #17 ships.

import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  runScanPipeline,
  type ScanInput,
  type ScanPipelineResult,
} from '../src/scanner/run-scan.js';

// Scorecard-blended categories vary with live GitHub API state — excluded from
// the determinism check (mirrors benchmark.ts SCORECARD_BLENDED / issue #17).
const DETERMINISM_EXCLUDE = new Set([
  'maintenance_community',
  'cicd_devops',
  'repo_security_posture',
  'workflow_security',
]);

const PHASE_KEYS = [
  'clone',
  'detect',
  'phaseA',
  'phaseB',
  'phaseC',
  'phaseD',
  'scoring',
  'cleanup',
];
const TOOL_KEYS = [
  'scorecard',
  'gitleaks',
  'lizard',
  'jscpd',
  'docsCheck',
  'cicdCheck',
  'trivy',
  'opengrep',
];

const [, , repoArg, branchArg] = process.argv;
const REPO = repoArg ?? 'sindresorhus/slugify';
const BRANCH = branchArg ?? 'main';
const [OWNER, NAME] = REPO.split('/');

// Frozen metadata reused across both runs so repository_overview / maintenance
// inputs are identical (isolates any nondeterminism to the tools themselves).
function makeInput(): ScanInput {
  return {
    scanId: randomUUID(),
    repoOwner: OWNER!,
    repoName: NAME!,
    defaultBranch: BRANCH,
    sizeKb: 500,
    isPrivate: false,
    pushedAt: new Date('2025-01-01T00:00:00Z'),
    stars: 100,
    language: 'JavaScript',
    isFork: false,
    description: 'e2e determinism fixture',
  };
}

function categoryMap(r: ScanPipelineResult): Map<string, number> {
  return new Map(r.result.categories.map((c) => [c.category, c.score]));
}

async function scanOnce(label: string): Promise<ScanPipelineResult> {
  const start = Date.now();
  const res = await runScanPipeline(makeInput(), { signal: AbortSignal.timeout(4 * 60 * 1000) });
  process.stderr.write(
    `[${label}] score=${res.result.overallScore} applicable=${res.result.applicableCount} files=${res.fileCount} wall=${((Date.now() - start) / 1000).toFixed(1)}s\n`,
  );
  return res;
}

function assertShape(r: ScanPipelineResult): void {
  const { result, timings, fileCount } = r;

  assert.equal(typeof result.overallScore, 'number', 'overallScore is a number');
  assert.ok(Number.isFinite(result.overallScore), 'overallScore is finite');
  assert.ok(result.overallScore >= 0 && result.overallScore <= 100, 'overallScore in [0,100]');
  assert.ok(result.categories.length > 0, 'has category scores');
  assert.ok(result.applicableCount >= 1, 'at least one applicable category');
  assert.ok(fileCount > 0, 'detected at least one file');

  // every phase/tool key is present (issue: per-phase + per-tool timing)
  for (const k of PHASE_KEYS) assert.ok(k in timings.phases, `timings.phases has ${k}`);
  for (const k of TOOL_KEYS) assert.ok(k in timings.tools, `timings.tools has ${k}`);

  // phases/tools that always run must show real (>0ms) time
  assert.ok(timings.phases.clone > 0, 'clone phase timed');
  assert.ok(timings.phases.phaseC > 0, 'phase C (Trivy) timed');
  assert.ok(timings.phases.phaseD > 0, 'phase D (Opengrep) timed');
  assert.ok(timings.tools.gitleaks > 0, 'gitleaks timed (always runs)');
  assert.ok(timings.tools.trivy > 0, 'trivy timed (always runs)');
  assert.ok(timings.tools.opengrep > 0, 'opengrep timed (always runs)');
  // scoring/cleanup can round to 0ms on tiny repos — just assert non-negative
  assert.ok(timings.phases.scoring >= 0, 'scoring phase non-negative');
  assert.ok(timings.phases.cleanup >= 0, 'cleanup phase non-negative');
}

async function main(): Promise<void> {
  process.stderr.write(`[pipeline-e2e] scanning ${REPO}@${BRANCH} twice\n`);

  const run1 = await scanOnce('run1');
  assertShape(run1);

  const run2 = await scanOnce('run2');
  assertShape(run2);

  // determinism: non-excluded categories must be byte-identical across runs
  const m1 = categoryMap(run1);
  const m2 = categoryMap(run2);
  const drifted: string[] = [];
  for (const [cat, s1] of m1) {
    if (DETERMINISM_EXCLUDE.has(cat)) continue;
    const s2 = m2.get(cat);
    if (s2 !== undefined && s2 !== s1) drifted.push(`${cat}: run1=${s1} run2=${s2}`);
  }
  if (drifted.length > 0) {
    process.stderr.write('[pipeline-e2e] NONDETERMINISM (a bug per #17):\n');
    for (const d of drifted) process.stderr.write(`  ${d}\n`);
  }
  assert.equal(drifted.length, 0, 'scoring deterministic across runs (non-Scorecard subset)');

  console.log('pipeline-e2e.check: all assertions passed');
}

main()
  // scorecard-tokens.ts (imported transitively) opens a bullRedis connection that
  // keeps the event loop alive — exit explicitly so the process doesn't hang.
  .then(() => process.exit(0))
  .catch((err) => {
    process.stderr.write(`\npipeline-e2e.check FAILED: ${(err as Error).message}\n`);
    process.stderr.write(
      'Hint: this test needs git + trivy + opengrep + gitleaks + jscpd + lizard on PATH ' +
        '(present in the worker Docker image / on the CX53, not on a bare dev box).\n',
    );
    process.exit(1);
  });
