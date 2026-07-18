// TEMPORARY test (issue #17) — drive REAL scans through the RUNNING worker
// container. Seeds scan rows + enqueues jobs on the github-scans queue; the
// already-running gitagrip-worker container (which has the tool binaries)
// processes them. Asserts the full production path: completion, DB persistence,
// per-tool/per-phase timings returned via job.returnvalue, and scoring
// determinism (non-Scorecard subset) across two runs of the same repo.
//
// Run from the HOST (has tsx; talks to the containers' exposed pg/redis). The
// worker IMAGE must be current (rebuilt after the #17 changes):
//   DATABASE_URL=postgresql://gitagrip:gitagrip@localhost:5432/gitagrip \
//   REDIS_URL=redis://localhost:6379 \
//   pnpm --filter @gitagrip/api exec tsx scripts/live-stack.check.ts [owner/repo ...]
//
// Delete once #17 ships.

import assert from 'node:assert/strict';
import { Queue, QueueEvents } from 'bullmq';
import { eq } from 'drizzle-orm';
import { db } from '../src/db/index.js';
import { scans, scanCategories } from '../src/db/schema.js';
import { bullRedis } from '../src/db/bull-redis.js';
import { PHASE_KEYS, SCORECARD_BLENDED, TOOL_KEYS } from '../src/scanner/run-scan.js';

const REPOS = process.argv.slice(2).filter((a) => !a.startsWith('-'));
if (REPOS.length === 0) REPOS.push('sindresorhus/slugify', 'bridgecrewio/terragoat');

interface Meta {
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

// same allowlist clone.ts uses before interpolating names into a URL
const SAFE_NAME = /^[a-zA-Z0-9._-]+$/;

async function fetchMeta(repo: string): Promise<Meta> {
  const [owner, name] = repo.split('/');
  if (!owner || !name || !SAFE_NAME.test(owner) || !SAFE_NAME.test(name)) {
    throw new Error(`Invalid repo "${repo}" — expected owner/name ([a-zA-Z0-9._-])`);
  }
  const token = (process.env.SCORECARD_GITHUB_TOKENS ?? '').split(',')[0]?.trim();
  const res = await fetch(`https://api.github.com/repos/${owner}/${name}`, {
    headers: {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok)
    throw new Error(
      `GitHub API ${res.status} for ${repo} (rate limit? set SCORECARD_GITHUB_TOKENS)`,
    );
  const b = (await res.json()) as Record<string, unknown>;
  return {
    id: b.id as number,
    owner: (b.owner as { login: string }).login,
    name: b.name as string,
    private: b.private as boolean,
    fork: b.fork as boolean,
    defaultBranch: b.default_branch as string,
    language: (b.language as string | null) ?? null,
    description: (b.description as string | null) ?? null,
    stars: (b.stargazers_count as number) ?? 0,
    sizeKb: (b.size as number) ?? 0,
    pushedAt: b.pushed_at ? new Date(b.pushed_at as string) : null,
  };
}

async function seed(meta: Meta): Promise<string> {
  const [row] = await db
    .insert(scans)
    .values({
      githubRepoId: meta.id,
      repoOwner: meta.owner,
      repoName: meta.name,
      isPrivate: meta.private,
      isFork: meta.fork,
      defaultBranch: meta.defaultBranch,
      language: meta.language,
      description: meta.description,
      stars: meta.stars,
      sizeKb: meta.sizeKb,
      pushedAt: meta.pushedAt,
      status: 'queued',
    })
    .returning({ id: scans.id });
  return row!.id;
}

interface ReturnValue {
  timings: { phases: Record<string, number>; tools: Record<string, number> };
  score: number;
  applicableCount: number;
  fileCount: number;
  sizeKb: number;
}

async function enqueueAndWait(
  queue: Queue,
  queueEvents: QueueEvents,
  scanId: string,
  meta: Meta,
): Promise<ReturnValue | null> {
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
  try {
    return (await job.waitUntilFinished(queueEvents, 10 * 60 * 1000)) as ReturnValue;
  } catch {
    return null; // job failed — DB assertions below surface the reason
  }
}

async function categoriesFor(scanId: string): Promise<Map<string, string>> {
  const rows = await db
    .select({ category: scanCategories.category, score: scanCategories.score })
    .from(scanCategories)
    .where(eq(scanCategories.scanId, scanId));
  return new Map(rows.map((r) => [r.category, r.score]));
}

async function assertCompleted(repo: string, scanId: string): Promise<number> {
  const [row] = await db
    .select({ status: scans.status, score: scans.score, errorMessage: scans.errorMessage })
    .from(scans)
    .where(eq(scans.id, scanId));
  assert.equal(
    row!.status,
    'completed',
    `${repo}: status completed (got ${row!.status}: ${row!.errorMessage})`,
  );
  assert.notEqual(row!.score, null, `${repo}: overall score persisted`);
  const cats = await categoriesFor(scanId);
  assert.ok(cats.size > 0, `${repo}: scan_categories persisted`);
  return row!.score!;
}

async function main(): Promise<void> {
  const queue = new Queue('github-scans', { connection: bullRedis });
  const queueEvents = new QueueEvents('github-scans', { connection: bullRedis });
  await queueEvents.waitUntilReady();
  const seededIds: string[] = [];

  try {
    // freeze one metadata snapshot per repo (reused for the determinism re-run)
    const metaByRepo = new Map<string, Meta>();
    for (const repo of REPOS) metaByRepo.set(repo, await fetchMeta(repo));

    const firstScanId = new Map<string, string>();

    for (const repo of REPOS) {
      const meta = metaByRepo.get(repo)!;
      process.stderr.write(`[live] scanning ${repo}@${meta.defaultBranch} (${meta.sizeKb}KB)...\n`);
      const scanId = await seed(meta);
      seededIds.push(scanId);
      const rv = await enqueueAndWait(queue, queueEvents, scanId, meta);

      const score = await assertCompleted(repo, scanId);
      firstScanId.set(repo, scanId);

      // the rebuilt worker must return per-phase/per-tool timings via job.returnvalue
      assert.ok(rv, `${repo}: worker returned a value (rebuild the worker image if this fails)`);
      for (const k of PHASE_KEYS)
        assert.ok(k in rv.timings.phases, `${repo}: timings.phases has ${k}`);
      for (const k of TOOL_KEYS)
        assert.ok(k in rv.timings.tools, `${repo}: timings.tools has ${k}`);
      assert.ok((rv.timings.tools.trivy ?? 0) > 0, `${repo}: trivy actually ran`);
      assert.ok(rv.fileCount > 0, `${repo}: files detected`);

      const t = rv.timings.tools;
      process.stderr.write(
        `[live] ${repo}: score=${score} files=${rv.fileCount} | trivy=${t.trivy}ms opengrep=${t.opengrep}ms gitleaks=${t.gitleaks}ms scorecard=${t.scorecard}ms\n`,
      );
    }

    // determinism: re-scan the first repo with the same frozen metadata, diff the
    // non-Scorecard categories (Scorecard is excluded — live GitHub API state).
    const detRepo = REPOS[0]!;
    process.stderr.write(`[live] determinism: re-scanning ${detRepo}...\n`);
    const scanId2 = await seed(metaByRepo.get(detRepo)!);
    seededIds.push(scanId2);
    await enqueueAndWait(queue, queueEvents, scanId2, metaByRepo.get(detRepo)!);
    await assertCompleted(detRepo, scanId2);

    const cats1 = await categoriesFor(firstScanId.get(detRepo)!);
    const cats2 = await categoriesFor(scanId2);
    const drift: string[] = [];
    for (const [cat, s1] of cats1) {
      if (SCORECARD_BLENDED.has(cat)) continue;
      const s2 = cats2.get(cat);
      if (s2 !== undefined && s2 !== s1) drift.push(`${cat}: run1=${s1} run2=${s2}`);
    }
    if (drift.length > 0) {
      process.stderr.write('[live] NONDETERMINISM (a bug per #17):\n');
      for (const d of drift) process.stderr.write(`  ${d}\n`);
    }
    assert.equal(drift.length, 0, `${detRepo}: deterministic across runs (non-Scorecard subset)`);
    process.stderr.write(`[live] determinism PASS for ${detRepo}\n`);

    console.log('live-stack.check: all assertions passed');
  } finally {
    for (const id of seededIds)
      await db
        .delete(scans)
        .where(eq(scans.id, id))
        .catch(() => {});
    await queue.close().catch(() => {});
    await queueEvents.close().catch(() => {});
    await bullRedis.quit().catch(() => {});
    await db.$client.end().catch(() => {});
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    process.stderr.write(`\nlive-stack.check FAILED: ${(err as Error).message}\n`);
    process.exit(1);
  });
