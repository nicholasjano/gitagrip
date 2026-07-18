// Standalone benchmark for the scan pipeline (issue #17).
// Runs the real pipeline over 9 tiered repos via real BullMQ + worker threads,
// captures per-tool/per-phase timings + process-tree peak RSS, runs a determinism
// pass, and emits a BenchmarkReport JSON + a stdout summary table.
//
// Usage:
//   pnpm --filter @gitagrip/api benchmark -- --repos owner/repo,... --workers 3 --output report.json
//
// --workers N sets the primary load-test concurrency (pass c). Passes a/b run at
// concurrency 1 (isolated timing baseline + determinism); pass d runs at N-1 for
// the throughput-vs-memory comparison.
//
// Must run where the tool binaries, Postgres, and Redis are available (CX53 or
// the worker Docker image). Pre-warm Trivy DB first:
//   trivy image --download-db-only

import { type Worker, Queue, QueueEvents } from 'bullmq';
import { eq, inArray, sql } from 'drizzle-orm';
import { writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import os from 'os';
import { db } from '../db/index.js';
import { scanCategories, scans, users } from '../db/schema.js';
import { bullRedis } from '../db/bull-redis.js';
import { buildScanWorker } from '../worker/build-scan-worker.js';
import { emptyTimings, SCORECARD_BLENDED, type ScanTimings } from './run-scan.js';
import { startRssSampler } from './rss-sampler.js';

// ─── CLI args ────────────────────────────────────────────────────────────────

interface CliArgs {
  repos: string[];
  workers: number;
  output: string;
}

export function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = { repos: [], workers: 3, output: 'benchmark-report.json' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--repos')
      args.repos = (argv[++i] ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    else if (a === '--workers') args.workers = Number(argv[++i] ?? '3');
    else if (a === '--output') args.output = argv[++i] ?? args.output;
  }
  if (args.repos.length === 0) args.repos = DEFAULT_REPOS.map((r) => r.repo);
  return args;
}

// ─── Test repo selection ─────────────────────────────────────────────────────
// Tiered to exercise the pipeline across size/tech axes. Constraints from #17:
// ≥1 Dockerfile, ≥1 IaC, ≥1 GitHub Actions; ≥1 repo that yields findings
// (terragoat). Implementer verified each against the GitHub size field and the
// 2 GB clone cap (clone.ts MAX_REPO_SIZE_KB) before locking the set.

export type Tier = 'small' | 'medium' | 'large';

export interface BenchmarkRepo {
  repo: string; // owner/name
  tier: Tier;
  note: string;
}

export const DEFAULT_REPOS: BenchmarkRepo[] = [
  // small (<10 MB, ~50 files)
  { repo: 'chalk/chalk', tier: 'small', note: 'utility lib' },
  { repo: 'sindresorhus/execa', tier: 'small', note: 'CLI-ish util' },
  { repo: 'bridgecrewio/terragoat', tier: 'small', note: 'IaC (Terraform) — yields findings' },
  // medium (~50 MB, ~500 files)
  { repo: 'expressjs/express', tier: 'medium', note: 'API; GitHub Actions' },
  { repo: 'reduxjs/redux', tier: 'medium', note: 'React ecosystem; Actions' },
  { repo: 'go-chi/chi', tier: 'medium', note: 'Go service; Dockerfile' },
  // large (>200 MB, ~2000 files)
  { repo: 'nestjs/nest', tier: 'large', note: 'framework monorepo; Dockerfile + Actions' },
  { repo: 'strapi/strapi', tier: 'large', note: 'large OSS; Actions' },
  { repo: 'grafana/grafana', tier: 'large', note: 'large OSS; IaC/compose + Actions' },
];

// Derive a tier from the GitHub `size` field (KB) for repos passed via --repos
// that aren't presets. Thresholds match the issue #17 tier definitions:
// small <10 MB, medium <200 MB, large otherwise.
export function tierForSizeKb(sizeKb: number): Tier {
  if (sizeKb < 10 * 1024) return 'small';
  if (sizeKb < 200 * 1024) return 'medium';
  return 'large';
}

// ─── GitHub metadata snapshot ────────────────────────────────────────────────

interface RepoMetadata {
  id: number;
  owner: string;
  name: string;
  private: boolean;
  fork: boolean;
  defaultBranch: string;
  language: string | null;
  description: string | null;
  stars: number;
  sizeKb: number;
  pushedAt: Date | null;
}

function pickScorecardToken(): string {
  const tokens = (process.env.SCORECARD_GITHUB_TOKENS ?? '')
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);
  if (tokens.length === 0) throw new Error('SCORECARD_GITHUB_TOKENS not set');
  return tokens[0]!;
}

// same allowlist clone.ts uses before interpolating names into a URL — keeps an
// operator-supplied "foo/bar?x=y" from reaching an unintended endpoint.
const SAFE_NAME = /^[a-zA-Z0-9._-]+$/;

async function fetchRepoMetadata(repo: string): Promise<RepoMetadata> {
  const [owner, name] = repo.split('/');
  if (!owner || !name || !SAFE_NAME.test(owner) || !SAFE_NAME.test(name)) {
    throw new Error(`Invalid repo "${repo}" — expected owner/name ([a-zA-Z0-9._-])`);
  }
  const token = pickScorecardToken();
  const res = await fetch(`https://api.github.com/repos/${owner}/${name}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
  if (!res.ok) throw new Error(`GitHub API ${res.status} for ${repo}`);
  const body = (await res.json()) as {
    id: number;
    name: string;
    owner: { login: string };
    private: boolean;
    fork: boolean;
    default_branch: string;
    language: string | null;
    description: string | null;
    stargazers_count: number;
    size: number;
    pushed_at: string;
  };
  return {
    id: body.id,
    owner: body.owner.login,
    name: body.name,
    private: body.private,
    fork: body.fork,
    defaultBranch: body.default_branch,
    language: body.language,
    description: body.description,
    stars: body.stargazers_count,
    sizeKb: body.size,
    pushedAt: body.pushed_at ? new Date(body.pushed_at) : null,
  };
}

// RSS sampling lives in rss-sampler.ts (extracted per PR review — separable module).

// ─── Scan row + job seeding ──────────────────────────────────────────────────

interface SeededScan {
  scanId: string;
  repo: string;
  tier: Tier;
  metadata: RepoMetadata;
  job: {
    id: string;
    wait: Promise<ScanJobWaitResult>;
  };
}

interface ScanJobWaitResult extends ScanTimings {
  score: number;
  fileCount: number;
  sizeKb: number;
  __error?: string;
}

async function seedScanRow(meta: RepoMetadata, requestedBy: string): Promise<string> {
  const [row] = await db
    .insert(scans)
    .values({
      requestedBy,
      githubRepoId: meta.id,
      repoOwner: meta.owner,
      repoName: meta.name,
      isPrivate: meta.private,
      isFork: meta.fork,
      defaultBranch: meta.defaultBranch,
      language: meta.language,
      stars: meta.stars,
      sizeKb: meta.sizeKb,
      pushedAt: meta.pushedAt,
      description: meta.description,
      status: 'queued',
    })
    .returning({ id: scans.id });
  if (!row) throw new Error(`failed to seed scan row for ${meta.owner}/${meta.name}`);
  return row.id;
}

// Build a fresh worker at a given concurrency. Caller must close() it.
// Delegates to the shared factory so the benchmark can't drift from prod options.
function buildWorker(concurrency: number): Worker {
  return buildScanWorker(concurrency);
}

// ─── Run a single pass over N repos at a given concurrency ───────────────────

export interface PerRepoResult {
  repo: string;
  tier: Tier;
  sizeKb: number;
  fileCount: number;
  phases: Record<string, number>;
  tools: Record<string, number>;
  peakMemoryMb: number;
  overallScore: number;
  applicableCategories: number;
  totalDurationMs: number;
  error?: string;
}

interface PassResult {
  results: PerRepoResult[];
  peakMemoryMb: number;
  totalWallMs: number;
  /** per-repo category scores keyed by this pass's exact scanId (determinism diff) */
  categoryScores: Map<string, Array<{ category: string; score: string }>>;
}

async function runPass(
  repos: BenchmarkRepo[],
  metadata: Map<string, RepoMetadata>,
  concurrency: number,
  workerPid: number,
  userId: string,
  queueEvents: QueueEvents,
  isDeterminismPass: boolean,
  seededScanIds: string[],
): Promise<PassResult> {
  const worker = buildWorker(concurrency);
  const queue = new Queue('github-scans', { connection: bullRedis });
  const rssTracker = startRssSampler(workerPid);

  try {
    // seed rows + enqueue, capturing each job's waitUntilFinished promise
    const seeded: SeededScan[] = [];
    for (const r of repos) {
      const meta = metadata.get(r.repo);
      if (!meta) throw new Error(`no metadata for ${r.repo}`);
      const scanId = await seedScanRow(meta, userId);
      seededScanIds.push(scanId);

      const job = await queue.add(
        'scan-repo',
        {
          scanId,
          repoOwner: meta.owner,
          repoName: meta.name,
          githubRepoId: meta.id,
          defaultBranch: meta.defaultBranch,
          sizeKb: meta.sizeKb,
        },
        { jobId: scanId },
      );

      const wait = job
        .waitUntilFinished(queueEvents, 10 * 60 * 1000)
        .then((rv): ScanJobWaitResult => {
          const ret = (rv ?? {}) as {
            timings?: ScanTimings;
            score?: number;
            fileCount?: number;
            sizeKb?: number;
          };
          return {
            ...(ret.timings ?? emptyTimings()),
            score: ret.score ?? 0,
            fileCount: ret.fileCount ?? 0,
            sizeKb: ret.sizeKb ?? 0,
          };
        })
        .catch((err): ScanJobWaitResult | Promise<ScanJobWaitResult> => {
          // job failed — read score back from DB; return a synthetic timing set
          return (async () => {
            const [row] = await db
              .select({ score: scans.score })
              .from(scans)
              .where(eq(scans.id, scanId))
              .limit(1);
            return {
              ...emptyTimings(),
              score: row?.score ?? 0,
              fileCount: 0,
              sizeKb: 0,
              __error: (err as Error).message,
            };
          })();
        });

      seeded.push({
        scanId,
        repo: r.repo,
        tier: r.tier,
        metadata: meta,
        job: { id: job.id!, wait },
      });
    }

    // collect results as they finish
    const results: PerRepoResult[] = [];
    const categoryScores = new Map<string, Array<{ category: string; score: string }>>();
    const passStart = Date.now();

    for (const s of seeded) {
      // In the sequential pass, one repo is in flight at a time, so zero the peak
      // before its window for clean per-repo attribution. Under concurrent load
      // repos overlap and per-repo peak can't be isolated — keep the pass peak.
      if (concurrency === 1) rssTracker.reset();
      const wallStart = Date.now();
      const rv = await s.job.wait;
      const wallMs = Date.now() - wallStart;

      // read back persisted categories for the determinism diff + applicableCount
      const categoryRows = await db
        .select({
          category: scanCategories.category,
          score: scanCategories.score,
          applicable: scanCategories.applicable,
        })
        .from(scanCategories)
        .where(eq(scanCategories.scanId, s.scanId));

      const applicableCategories = categoryRows.filter((c) => c.applicable).length;
      const peakMemoryMb = Math.round((rssTracker.peak ?? 0) / 1024);

      // thread the exact scanId-keyed scores out so the determinism diff doesn't
      // have to re-query by a fragile "latest by createdAt" heuristic.
      categoryScores.set(
        s.repo,
        categoryRows.map((c) => ({ category: c.category, score: c.score })),
      );

      results.push({
        repo: s.repo,
        tier: s.tier,
        sizeKb: rv.sizeKb || s.metadata.sizeKb,
        fileCount: rv.fileCount,
        phases: rv.phases,
        tools: rv.tools,
        peakMemoryMb,
        overallScore: rv.score,
        applicableCategories,
        totalDurationMs: wallMs,
        error: rv.__error,
      });

      // determinism log: per-category scores for the second-pass diff
      if (isDeterminismPass) {
        process.stdout.write(
          `[determinism] ${s.repo} categories: ${JSON.stringify(categoryRows.map((c) => ({ c: c.category, s: c.score })))}\n`,
        );
      }
    }

    return {
      results,
      peakMemoryMb: Math.round((rssTracker.peak ?? 0) / 1024),
      totalWallMs: Date.now() - passStart,
      categoryScores,
    };
  } finally {
    rssTracker.stop();
    await worker.close();
    await queue.close();
  }
}

// ─── Determinism check ───────────────────────────────────────────────────────
// Per #17: Scorecard-blended categories excluded (live API state), rest must
// match across two runs. Any diff is a bug.
// SCORECARD_BLENDED is re-exported from run-scan.ts (single source of truth).
export { SCORECARD_BLENDED };

export interface DeterminismDiff {
  repo: string;
  diffs: Array<{ category: string; run1: string; run2: string }>;
}

export function diffDeterminism(
  run1: PerRepoResult[],
  run2: PerRepoResult[],
  categoryScoresRun1: Map<string, Array<{ category: string; score: string }>>,
  categoryScoresRun2: Map<string, Array<{ category: string; score: string }>>,
): DeterminismDiff[] {
  const out: DeterminismDiff[] = [];
  for (const r1 of run1) {
    const r2 = run2.find((r) => r.repo === r1.repo);
    if (!r2) continue;
    const cats1 = new Map(
      (categoryScoresRun1.get(r1.repo) ?? []).map((c) => [c.category, c.score]),
    );
    const cats2 = categoryScoresRun2.get(r2.repo) ?? [];
    const diffs: Array<{ category: string; run1: string; run2: string }> = [];
    for (const c of cats2) {
      if (SCORECARD_BLENDED.has(c.category)) continue;
      const v1 = cats1.get(c.category);
      if (v1 !== undefined && v1 !== c.score) {
        diffs.push({ category: c.category, run1: v1, run2: c.score });
      }
    }
    if (diffs.length > 0) out.push({ repo: r1.repo, diffs });
  }
  return out;
}

// ─── Report ──────────────────────────────────────────────────────────────────

export interface BenchmarkReport {
  timestamp: string;
  serverSpec: string;
  workerCount: number;
  /** load-test concurrency (pass c); per-repo rows below are measured at concurrency 1 */
  concurrencyPerWorker: number;
  /** per-repo per-tool timings measured in isolation (concurrency 1) */
  repos: Array<{
    repo: string;
    sizeKb: number;
    fileCount: number;
    phases: Record<string, number>;
    tools: Record<string, number>;
    peakMemoryMb: number;
    overallScore: number;
    applicableCategories: number;
    totalDurationMs: number;
  }>;
  summary: {
    avgDurationByTier: Record<string, number>;
    avgToolDuration: Record<string, number>;
    slowestTool: string;
    fastestTool: string;
    peakMemoryMb: number;
    recommendations: string[];
  };
}

export function serverSpec(): string {
  const cpus = os.cpus().length;
  const totalMb = Math.round(os.totalmem() / (1024 * 1024));
  return `CX53 ${cpus}c/${totalMb}MB (${os.platform()}/${os.arch()})`;
}

export function buildReport(
  repos: PerRepoResult[],
  concurrency: number,
  peakMemoryMb: number,
): BenchmarkReport {
  // per-tier averages
  const byTier = new Map<Tier, number[]>();
  for (const r of repos) {
    const arr = byTier.get(r.tier) ?? [];
    arr.push(r.totalDurationMs);
    byTier.set(r.tier, arr);
  }
  const avgDurationByTier: Record<string, number> = {};
  for (const [tier, durations] of byTier) {
    avgDurationByTier[tier] = Math.round(durations.reduce((a, b) => a + b, 0) / durations.length);
  }

  // per-tool averages across repos
  const toolTotals: Record<string, number[]> = {};
  for (const r of repos) {
    for (const [tool, ms] of Object.entries(r.tools)) {
      const arr = toolTotals[tool] ?? [];
      arr.push(ms);
      toolTotals[tool] = arr;
    }
  }
  const avgToolDuration: Record<string, number> = {};
  for (const [tool, arr] of Object.entries(toolTotals)) {
    avgToolDuration[tool] = Math.round(arr.reduce((a, b) => a + b, 0) / arr.length);
  }
  const sortedTools = Object.entries(avgToolDuration).sort((a, b) => b[1] - a[1]);
  const slowestTool = sortedTools[0]?.[0] ?? 'n/a';
  const fastestTool = sortedTools[sortedTools.length - 1]?.[0] ?? 'n/a';

  // recommendations from the issue's thresholds
  const recommendations: string[] = [];
  for (const r of repos) {
    // percent of total SCAN time (wall clock incl. clone/scoring/cleanup), not
    // tool time — otherwise clone (which dominates wall time) isn't counted and
    // the 60% flag over-fires. #17: "Tool > 60% of total scan time".
    const scanMs = r.totalDurationMs;
    for (const [tool, ms] of Object.entries(r.tools)) {
      if (scanMs > 0 && ms / scanMs > 0.6) {
        recommendations.push(
          `${r.repo}: ${tool} is ${((ms / scanMs) * 100).toFixed(0)}% of total scan time — flag for skip/timeout reduction`,
        );
      }
    }
    if (r.tier === 'large' && (r.tools.opengrep ?? 0) > 90_000) {
      recommendations.push(
        `${r.repo}: opengrep ${r.tools.opengrep}ms on large repo — reduce rule set or raise -j (currently -j 2)`,
      );
    }
    if ((r.tools.scorecard ?? 0) > 90_000) {
      recommendations.push(
        `${r.repo}: scorecard ${r.tools.scorecard}ms — consider caching recently-scanned repos`,
      );
    }
    if ((r.tools.jscpd ?? 0) < 5_000 && (r.tools.lizard ?? 0) < 5_000) {
      recommendations.push(
        `${r.repo}: jscpd (${r.tools.jscpd}ms) + lizard (${r.tools.lizard}ms) both <5s — confirm worth keeping (cheap, unique data)`,
      );
    }
  }
  if (peakMemoryMb > 5 * 1024) {
    recommendations.push(
      `Concurrent-pass peak RSS ${peakMemoryMb}MB > 5 GB — reduce worker concurrency from 3 to 2`,
    );
  }

  return {
    timestamp: new Date().toISOString(),
    serverSpec: serverSpec(),
    workerCount: 1,
    concurrencyPerWorker: concurrency,
    repos: repos.map((r) => ({
      repo: r.repo,
      sizeKb: r.sizeKb,
      fileCount: r.fileCount,
      phases: r.phases,
      tools: r.tools,
      peakMemoryMb: r.peakMemoryMb,
      overallScore: r.overallScore,
      applicableCategories: r.applicableCategories,
      totalDurationMs: r.totalDurationMs,
    })),
    summary: {
      avgDurationByTier,
      avgToolDuration,
      slowestTool,
      fastestTool,
      peakMemoryMb,
      recommendations,
    },
  };
}

function printStdoutTable(report: BenchmarkReport, tierByRepo: Map<string, Tier>): void {
  process.stdout.write(
    '\n┌─ Benchmark summary ─────────────────────────────────────────────────┐\n',
  );
  process.stdout.write(`│ server: ${report.serverSpec}\n`);
  process.stdout.write(
    `│ concurrency: ${report.concurrencyPerWorker}  peak RSS (under load): ${report.summary.peakMemoryMb}MB\n`,
  );
  process.stdout.write(
    `│ slowest tool: ${report.summary.slowestTool}   fastest: ${report.summary.fastestTool}\n`,
  );
  process.stdout.write('│ per-repo timings measured in isolation (concurrency 1)\n');
  process.stdout.write(
    '├──────────────────────┬──────────┬────────┬──────────┬───────────┬─────────┤\n',
  );
  process.stdout.write(
    '│ repo                 │ tier     │ score  │ peak(MB) │ total(s)  │ clone(s)│\n',
  );
  process.stdout.write(
    '├──────────────────────┼──────────┼────────┼──────────┼───────────┼─────────┤\n',
  );
  for (const r of report.repos) {
    const tier = (tierByRepo.get(r.repo) ?? '?').padEnd(8);
    const name = r.repo.length > 20 ? r.repo.slice(0, 20) : r.repo.padEnd(20);
    process.stdout.write(
      `│ ${name} │ ${tier} │ ${String(r.overallScore).padStart(6)} │ ${String(r.peakMemoryMb).padStart(8)} │ ${String((r.totalDurationMs / 1000).toFixed(1)).padStart(9)} │ ${String(((r.phases.clone ?? 0) / 1000).toFixed(1)).padStart(7)} │\n`,
    );
  }
  process.stdout.write(
    '└──────────────────────┴──────────┴────────┴──────────┴───────────┴─────────┘\n',
  );
  if (report.summary.recommendations.length > 0) {
    process.stdout.write('\nRecommendations:\n');
    for (const rec of report.summary.recommendations) process.stdout.write(`  - ${rec}\n`);
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  process.stdout.write(
    `[benchmark] ${args.repos.length} repos, workers=${args.workers}, output=${args.output}\n`,
  );

  // fetch metadata once and reuse across both determinism runs (freeze snapshot)
  const metadata = new Map<string, RepoMetadata>();
  for (const repoStr of args.repos) {
    process.stdout.write(`[benchmark] fetching metadata for ${repoStr}\n`);
    metadata.set(repoStr, await fetchRepoMetadata(repoStr));
  }

  // Build the tiered repo list. A --repos entry that matches a preset keeps its
  // curated tier/note; any other repo is tiered from its fetched GitHub size, so
  // --repos accepts ARBITRARY repos, not just the defaults.
  const repos: BenchmarkRepo[] = args.repos.map((repoStr) => {
    const preset = DEFAULT_REPOS.find((d) => d.repo === repoStr);
    if (preset) return preset;
    return { repo: repoStr, tier: tierForSizeKb(metadata.get(repoStr)!.sizeKb), note: 'custom' };
  });

  // ensure the benchmark has a valid user row to satisfy scans.requestedBy FK.
  // ponytail: reuse a stable benchmark user (github_id=0) rather than creating one each run.
  const BENCHMARK_USER_ID = '00000000-0000-0000-0000-000000000000';
  await db
    .execute(
      sql`INSERT INTO users (id, github_id, username, access_token)
          VALUES (${BENCHMARK_USER_ID}::uuid, 0, 'benchmark', 'benchmark')
          ON CONFLICT (github_id) DO NOTHING`,
    )
    .catch((err) => {
      // users table may not exist or schema differs — fall back to NULL requestedBy
      process.stderr.write(
        `[benchmark] benchmark user upsert skipped: ${(err as Error).message}\n`,
      );
    });

  const queueEvents = new QueueEvents('github-scans', { connection: bullRedis });
  const workerPid = process.pid;
  // every scan row seeded across all 4 passes — deleted in finally so the
  // benchmark leaves no fixture rows in whatever DATABASE_URL it pointed at.
  const seededScanIds: string[] = [];

  try {
    // pass a: sequential (concurrency 1) — clean per-repo timings + peak RSS + run 1 scores
    process.stdout.write('\n[benchmark] pass a: concurrency=1 (timings + run 1 scores)\n');
    const pass1 = await runPass(
      repos,
      metadata,
      1,
      workerPid,
      BENCHMARK_USER_ID,
      queueEvents,
      false,
      seededScanIds,
    );

    // pass b: determinism run 2 (concurrency 1) — diff vs run 1
    process.stdout.write('\n[benchmark] pass b: concurrency=1 (determinism run 2)\n');
    const pass2 = await runPass(
      repos,
      metadata,
      1,
      workerPid,
      BENCHMARK_USER_ID,
      queueEvents,
      true,
      seededScanIds,
    );
    const diffs = diffDeterminism(
      pass1.results,
      pass2.results,
      pass1.categoryScores,
      pass2.categoryScores,
    );
    if (diffs.length > 0) {
      process.stdout.write(
        `\n[determinism] ${diffs.length} repo(s) with nondeterministic scores:\n`,
      );
      for (const d of diffs) {
        process.stdout.write(`  ${d.repo}:\n`);
        for (const x of d.diffs) {
          process.stdout.write(`    ${x.category}: run1=${x.run1} run2=${x.run2}\n`);
        }
      }
    } else {
      process.stdout.write('\n[determinism] PASS — deterministic subset identical across runs\n');
    }

    // pass c: concurrent @ args.workers — throughput + aggregate peak RSS + OOM watch
    const primaryWorkers = args.workers;
    const secondaryWorkers = Math.max(1, primaryWorkers - 1);
    process.stdout.write(`\n[benchmark] pass c: concurrency=${primaryWorkers} (load test)\n`);
    const pass3 = await runPass(
      repos,
      metadata,
      primaryWorkers,
      workerPid,
      BENCHMARK_USER_ID,
      queueEvents,
      false,
      seededScanIds,
    );

    // pass d: concurrent @ (workers - 1) — throughput vs memory comparison
    process.stdout.write(`\n[benchmark] pass d: concurrency=${secondaryWorkers} (load test)\n`);
    const pass4 = await runPass(
      repos,
      metadata,
      secondaryWorkers,
      workerPid,
      BENCHMARK_USER_ID,
      queueEvents,
      false,
      seededScanIds,
    );

    // Per-repo rows come from the sequential pass (isolated, contention-free
    // per-tool timing + clean per-repo peak); summary peak RSS is the worst case
    // across the concurrent passes (the figure that drives the 5 GB decision).
    const summaryPeakMemoryMb = Math.max(pass3.peakMemoryMb, pass4.peakMemoryMb);
    const report = buildReport(pass1.results, primaryWorkers, summaryPeakMemoryMb);
    writeFileSync(args.output, JSON.stringify(report, null, 2));
    process.stdout.write(`\n[benchmark] wrote ${args.output}\n`);
    printStdoutTable(report, new Map(repos.map((r) => [r.repo, r.tier])));

    // throughput comparison for the human
    process.stdout.write(`\nThroughput:\n`);
    process.stdout.write(
      `  concurrency=${primaryWorkers}: ${(pass3.totalWallMs / 1000).toFixed(1)}s wall, peak ${pass3.peakMemoryMb}MB\n`,
    );
    process.stdout.write(
      `  concurrency=${secondaryWorkers}: ${(pass4.totalWallMs / 1000).toFixed(1)}s wall, peak ${pass4.peakMemoryMb}MB\n`,
    );
  } finally {
    // remove fixture rows: scan_categories cascades on scans delete; the stable
    // benchmark user (github_id=0) is dropped too so no phantom row persists.
    if (seededScanIds.length > 0) {
      await db
        .delete(scans)
        .where(inArray(scans.id, seededScanIds))
        .catch((err) => {
          process.stderr.write(
            `[benchmark] fixture scan cleanup failed: ${(err as Error).message}\n`,
          );
        });
    }
    await db
      .delete(users)
      .where(eq(users.id, BENCHMARK_USER_ID))
      .catch(() => undefined); // user may not have been upserted; best-effort
    await queueEvents.close();
    await bullRedis.quit();
    await db.$client.end();
  }
}

// Only auto-run when invoked directly (tsx src/scanner/benchmark.ts), not when
// imported by a test. Keeps the pure helpers unit-testable.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    process.stderr.write(`[benchmark] fatal: ${(err as Error).message}\n`);
    process.exit(1);
  });
}
