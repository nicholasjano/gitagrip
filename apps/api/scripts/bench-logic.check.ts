// TEMPORARY test (issue #17) — pure-logic checks for benchmark.ts. No infra.
// Validates the pieces that encode the issue's REQUIREMENTS: arg parsing, the
// tiered repo selection, the determinism-exclusion rule, and the optimization
// recommendation thresholds.
//
// Run (from apps/api). --env-file is only so importing benchmark.ts (which pulls
// in bull-redis) doesn't throw on a missing REDIS_URL — no DB/Redis is used here:
//   pnpm --filter @gitagrip/api exec tsx --env-file=../../.env scripts/bench-logic.check.ts
//
// Delete this file (and the other scripts/*.check.ts) once #17 ships.

import assert from 'node:assert/strict';
import {
  parseArgs,
  DEFAULT_REPOS,
  diffDeterminism,
  SCORECARD_BLENDED,
  buildReport,
  serverSpec,
  tierForSizeKb,
  type PerRepoResult,
} from '../src/scanner/benchmark.js';

// full PerRepoResult with sensible defaults; override per test
function mkRepo(over: Partial<PerRepoResult> & { repo: string }): PerRepoResult {
  return {
    tier: 'small',
    sizeKb: 1000,
    fileCount: 50,
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
    peakMemoryMb: 0,
    overallScore: 0,
    applicableCategories: 0,
    totalDurationMs: 0,
    ...over,
  };
}

function run(): void {
  // ── parseArgs ──────────────────────────────────────────────────────────────
  {
    const def = parseArgs([]);
    assert.equal(def.workers, 3, 'parseArgs: default workers=3');
    assert.equal(def.output, 'benchmark-report.json', 'parseArgs: default output');
    assert.equal(def.repos.length, DEFAULT_REPOS.length, 'parseArgs: default repos = all defaults');

    const custom = parseArgs(['--workers', '2', '--output', 'o.json', '--repos', 'a/b, c/d ']);
    assert.equal(custom.workers, 2, 'parseArgs: --workers parsed');
    assert.equal(custom.output, 'o.json', 'parseArgs: --output parsed');
    assert.deepEqual(custom.repos, ['a/b', 'c/d'], 'parseArgs: --repos split + trimmed');

    // empty --repos falls back to defaults
    assert.equal(
      parseArgs(['--repos', '']).repos.length,
      DEFAULT_REPOS.length,
      'parseArgs: empty --repos -> defaults',
    );
  }

  // ── DEFAULT_REPOS: the issue's tiered selection + tech-mix constraints ───────
  {
    assert.equal(DEFAULT_REPOS.length, 9, 'repos: 9 total (3 tiers x 3)');
    for (const tier of ['small', 'medium', 'large'] as const) {
      assert.equal(
        DEFAULT_REPOS.filter((r) => r.tier === tier).length,
        3,
        `repos: exactly 3 in ${tier} tier`,
      );
    }
    const notes = DEFAULT_REPOS.map((r) => r.note).join(' | ');
    assert.match(notes, /IaC/i, 'repos: at least one IaC repo (issue mix requirement)');
    assert.match(notes, /Dockerfile/i, 'repos: at least one Dockerfile repo');
    assert.match(notes, /Actions/i, 'repos: at least one GitHub Actions repo');
    // no duplicate repos
    assert.equal(new Set(DEFAULT_REPOS.map((r) => r.repo)).size, 9, 'repos: no duplicates');
  }

  // ── tierForSizeKb: --repos accepts arbitrary repos, tiered by GitHub size ────
  {
    assert.equal(tierForSizeKb(5_000), 'small', 'tier: <10 MB -> small');
    assert.equal(tierForSizeKb(10 * 1024), 'medium', 'tier: 10 MB boundary -> medium');
    assert.equal(tierForSizeKb(50 * 1024), 'medium', 'tier: ~50 MB -> medium');
    assert.equal(tierForSizeKb(199 * 1024), 'medium', 'tier: just under 200 MB -> medium');
    assert.equal(tierForSizeKb(200 * 1024), 'large', 'tier: 200 MB boundary -> large');
    assert.equal(tierForSizeKb(500 * 1024), 'large', 'tier: >200 MB -> large');
  }

  // ── SCORECARD_BLENDED: the documented determinism exclusion set ──────────────
  {
    assert.equal(SCORECARD_BLENDED.size, 4, 'exclusions: exactly 4 Scorecard-blended categories');
    for (const c of [
      'maintenance_community',
      'cicd_devops',
      'repo_security_posture',
      'workflow_security',
    ]) {
      assert.ok(SCORECARD_BLENDED.has(c), `exclusions: includes ${c}`);
    }
  }

  // ── diffDeterminism: core determinism-check requirement ──────────────────────
  {
    const run1 = [mkRepo({ repo: 'x/a' })];
    const run2 = [mkRepo({ repo: 'x/a' })];
    const base = new Map([
      [
        'x/a',
        [
          { category: 'security_vulnerabilities', score: '90' },
          { category: 'maintenance_community', score: '50' },
        ],
      ],
    ]);

    // identical -> no diffs
    assert.equal(
      diffDeterminism(run1, run2, base, base).length,
      0,
      'determinism: identical runs -> no diff',
    );

    // a differing NON-excluded category is flagged as a bug
    const changedSecurity = new Map([
      [
        'x/a',
        [
          { category: 'security_vulnerabilities', score: '80' },
          { category: 'maintenance_community', score: '50' },
        ],
      ],
    ]);
    const secDiff = diffDeterminism(run1, run2, base, changedSecurity);
    assert.equal(secDiff.length, 1, 'determinism: non-excluded diff -> flagged');
    assert.equal(secDiff[0]!.diffs.length, 1, 'determinism: one differing category');
    assert.equal(
      secDiff[0]!.diffs[0]!.category,
      'security_vulnerabilities',
      'determinism: right category',
    );
    assert.equal(secDiff[0]!.diffs[0]!.run1, '90', 'determinism: run1 value');
    assert.equal(secDiff[0]!.diffs[0]!.run2, '80', 'determinism: run2 value');

    // a differing EXCLUDED (Scorecard) category is NOT flagged
    const changedScorecard = new Map([
      [
        'x/a',
        [
          { category: 'security_vulnerabilities', score: '90' },
          { category: 'maintenance_community', score: '40' },
        ],
      ],
    ]);
    assert.equal(
      diffDeterminism(run1, run2, base, changedScorecard).length,
      0,
      'determinism: Scorecard-blended diff excluded',
    );

    // mixed: only the non-excluded category is reported
    const changedBoth = new Map([
      [
        'x/a',
        [
          { category: 'security_vulnerabilities', score: '80' },
          { category: 'maintenance_community', score: '40' },
        ],
      ],
    ]);
    const mixed = diffDeterminism(run1, run2, base, changedBoth);
    assert.equal(mixed.length, 1, 'determinism: mixed -> one repo flagged');
    assert.equal(mixed[0]!.diffs.length, 1, 'determinism: excluded diff dropped from mixed');
    assert.equal(
      mixed[0]!.diffs[0]!.category,
      'security_vulnerabilities',
      'determinism: only non-excluded reported',
    );
  }

  // ── buildReport: averages + the issue's optimization-decision thresholds ─────
  {
    const repos: PerRepoResult[] = [
      // tool > 60% of tool time -> "skip/timeout" flag (isolate: lizard/jscpd >= 5s so no cheap flag)
      mkRepo({
        repo: 'x/skip',
        tier: 'small',
        totalDurationMs: 10_000,
        tools: {
          scorecard: 500,
          gitleaks: 500,
          lizard: 6000,
          jscpd: 6000,
          docsCheck: 100,
          cicdCheck: 100,
          trivy: 80_000,
          opengrep: 500,
        },
      }),
      // opengrep > 90s on a large repo -> tune-rules flag
      mkRepo({
        repo: 'x/og',
        tier: 'large',
        totalDurationMs: 30_000,
        tools: {
          scorecard: 1000,
          gitleaks: 1000,
          lizard: 6000,
          jscpd: 6000,
          docsCheck: 1000,
          cicdCheck: 1000,
          trivy: 1000,
          opengrep: 95_000,
        },
      }),
      // scorecard > 90s -> cache flag
      mkRepo({
        repo: 'x/sc',
        tier: 'medium',
        totalDurationMs: 40_000,
        tools: {
          scorecard: 95_000,
          gitleaks: 1000,
          lizard: 6000,
          jscpd: 6000,
          docsCheck: 1000,
          cicdCheck: 1000,
          trivy: 1000,
          opengrep: 1000,
        },
      }),
      // jscpd + lizard < 5s -> "worth keeping" flag; no single tool > 60%
      mkRepo({
        repo: 'x/cheap',
        tier: 'small',
        totalDurationMs: 20_000,
        tools: {
          scorecard: 4000,
          gitleaks: 4000,
          lizard: 1000,
          jscpd: 1000,
          docsCheck: 4000,
          cicdCheck: 4000,
          trivy: 4000,
          opengrep: 4000,
        },
      }),
    ];

    const report = buildReport(repos, 3, 6000); // 6000 MB > 5 GB -> concurrency flag

    // per-tier averages: small = (10000 + 20000)/2, large = 30000, medium = 40000
    assert.equal(report.summary.avgDurationByTier.small, 15_000, 'report: small tier avg');
    assert.equal(report.summary.avgDurationByTier.large, 30_000, 'report: large tier avg');
    assert.equal(report.summary.avgDurationByTier.medium, 40_000, 'report: medium tier avg');

    // per-tool averages (arithmetic is deterministic regardless of tie ordering)
    assert.equal(report.summary.avgToolDuration.scorecard, 25_125, 'report: scorecard avg');
    assert.equal(report.summary.avgToolDuration.trivy, 21_500, 'report: trivy avg');
    // slowest/fastest resolve to a max/min-valued tool
    assert.equal(
      report.summary.avgToolDuration[report.summary.slowestTool],
      25_125,
      'report: slowestTool is a max',
    );
    assert.equal(
      report.summary.avgToolDuration[report.summary.fastestTool],
      1_525,
      'report: fastestTool is a min',
    );

    const recs = report.summary.recommendations;
    assert.ok(
      recs.some((r) => r.includes('x/skip') && r.includes('trivy') && /skip|timeout/.test(r)),
      'report: >60% tool time flagged',
    );
    assert.ok(
      recs.some((r) => r.includes('x/og') && r.includes('opengrep') && r.includes('-j')),
      'report: opengrep >90s on large repo flagged',
    );
    assert.ok(
      recs.some((r) => r.includes('x/sc') && /cach/i.test(r)),
      'report: scorecard >90s flagged',
    );
    assert.ok(
      recs.some((r) => r.includes('x/cheap') && /worth keeping/i.test(r)),
      'report: cheap jscpd+lizard flagged for keep',
    );
    assert.ok(
      recs.some((r) => /reduce worker concurrency/i.test(r)),
      'report: peak RSS > 5 GB flags concurrency reduction',
    );
    assert.equal(report.concurrencyPerWorker, 3, 'report: concurrency echoed');
    assert.equal(report.repos.length, 4, 'report: per-repo rows present');

    // under 5 GB -> no concurrency-reduction recommendation
    const lowMem = buildReport(repos, 3, 3000);
    assert.ok(
      !lowMem.summary.recommendations.some((r) => /reduce worker concurrency/i.test(r)),
      'report: peak RSS < 5 GB -> no concurrency flag',
    );
  }

  // ── #5: >60% flag uses WALL time, not tool-time-sum ─────────────────────────
  {
    // trivy is 70% of tool-time (7000/10000) but only 35% of the 20s wall time
    // (clone dominates). The flag must NOT fire — wall time is the denominator.
    const cloneDominated = buildReport(
      [
        mkRepo({
          repo: 'x/wall',
          totalDurationMs: 20_000,
          phases: { ...mkRepo({ repo: 'x' }).phases, clone: 12_000 },
          tools: {
            scorecard: 1000,
            gitleaks: 1000,
            lizard: 6000,
            jscpd: 6000,
            docsCheck: 0,
            cicdCheck: 0,
            trivy: 7000,
            opengrep: 1000,
          },
        }),
      ],
      3,
      1000,
    );
    assert.ok(
      !cloneDominated.summary.recommendations.some((r) => /60%|of total scan time/i.test(r)),
      'report: >60% flag uses wall time (clone-dominated scan not flagged)',
    );
    // ...and the inverse: 13s of a 20s wall is 65% -> must fire
    const fires = buildReport(
      [
        mkRepo({
          repo: 'x/wall2',
          totalDurationMs: 20_000,
          tools: {
            scorecard: 1000,
            gitleaks: 0,
            lizard: 6000,
            jscpd: 6000,
            docsCheck: 0,
            cicdCheck: 0,
            trivy: 13_000,
            opengrep: 0,
          },
        }),
      ],
      3,
      1000,
    );
    assert.ok(
      fires.summary.recommendations.some((r) => /of total scan time/i.test(r)),
      'report: tool >60% of wall time flagged',
    );
  }

  // ── serverSpec ───────────────────────────────────────────────────────────────
  {
    const spec = serverSpec();
    assert.match(spec, /^CX53 /, 'serverSpec: labeled CX53');
    assert.match(spec, /c\//, 'serverSpec: cpu count');
    assert.match(spec, /MB/, 'serverSpec: memory');
  }

  console.log('bench-logic.check: all assertions passed');
}

run();
// bull-redis opened a lazy connection on import; exit so the event loop doesn't hang.
process.exit(0);
