// scan submission business logic
// sits between routes and the queue — routes stay thin, logic stays testable

import { Job } from 'bullmq';
import { eq, sql, desc } from 'drizzle-orm';
import { db } from '../db/index.js';
import { scans, scanBatches, type ScanSelect } from '../db/schema.js';
import { scanQueue } from '../queue/scan-queue.js';
import { flowProducer } from '../queue/flow-producer.js';
import { decrypt } from '../lib/crypto.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SingleScanResult {
  scanId: string;
  jobId: string;
}

export interface BatchScanResult {
  batchId: string;
  totalRepos: number;
}

export interface CooldownError {
  type: 'cooldown';
  retryAfter: Date;
}

export interface ScanStatusResult {
  status: ScanSelect['status'] | string;
  score?: number | null;
  progress?: number;
  scan?: ScanSelect;
}

// github repo metadata shape returned by the GitHub REST API
interface GitHubRepo {
  id: number;
  name: string;
  owner: { login: string };
  private: boolean;
  fork: boolean;
  default_branch: string;
  language: string | null;
  stargazers_count: number;
  size: number;
  pushed_at: string;
}

const COOLDOWN_MS = 3 * 60 * 60 * 1000; // 3 hours in ms
const GITHUB_MAX_RETRIES = 3;

async function fetchGitHubWithRetry(url: string, accessToken: string): Promise<Response> {
  let lastResponse: Response | null = null;

  for (let attempt = 1; attempt <= GITHUB_MAX_RETRIES; attempt++) {
    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });

    if (res.status < 500) {
      return res;
    }

    lastResponse = res;
    if (attempt < GITHUB_MAX_RETRIES) {
      await new Promise((resolve) => setTimeout(resolve, attempt * 500));
    }
  }

  return lastResponse!;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// fetch a single repo's metadata from GitHub API using the user's access token
async function fetchGitHubRepo(
  owner: string,
  name: string,
  accessToken: string,
): Promise<GitHubRepo> {
  const res = await fetchGitHubWithRetry(
    `https://api.github.com/repos/${owner}/${name}`,
    accessToken,
  );

  if (!res.ok) {
    if (res.status === 404) throw new Error(`Repository ${owner}/${name} not found`);
    if (res.status === 403) throw new Error('GitHub API rate limit exceeded');
    throw new Error(`GitHub API error: ${res.status}`);
  }

  return res.json() as Promise<GitHubRepo>;
}

// fetch all repos for a user or org, paginating through all pages
async function fetchGitHubRepos(
  type: 'user' | 'org',
  target: string,
  accessToken: string,
): Promise<GitHubRepo[]> {
  const repos: GitHubRepo[] = [];
  let page = 1;

  while (true) {
    const endpoint =
      type === 'org'
        ? `https://api.github.com/orgs/${target}/repos`
        : `https://api.github.com/users/${target}/repos`;

    const res = await fetchGitHubWithRetry(
      `${endpoint}?per_page=100&page=${page}&type=all`,
      accessToken,
    );

    if (!res.ok) {
      if (res.status === 404) throw new Error(`${type} "${target}" not found on GitHub`);
      if (res.status === 403) throw new Error('GitHub API rate limit exceeded');
      throw new Error(`GitHub API error: ${res.status}`);
    }

    const page_repos = (await res.json()) as GitHubRepo[];
    repos.push(...page_repos);

    // GitHub returns fewer than 100 items on the last page
    if (page_repos.length < 100) break;
    page++;
  }

  return repos;
}

// acquire a postgres advisory lock for the duration of the transaction.
// this is a named mutex — two transactions trying to lock the same name
// will queue up. the second one waits until the first commits/rolls back.
// we use this to prevent two simultaneous scan submissions for the same repo
// from both passing the cooldown check before either inserts the scan row.
//
// uses two-argument form for a 64-bit keyspace (namespace + key).
// single-argument hashtext() only gives 32 bits, which hits birthday-paradox
// collisions at ~100K distinct keys.
async function withAdvisoryLock<T>(
  tx: Parameters<Parameters<typeof db.transaction>[0]>[0],
  namespace: string,
  key: string,
  fn: () => Promise<T>,
): Promise<T> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${namespace}), hashtext(${key}))`);
  return fn();
}

// ─── submitSingleScan ─────────────────────────────────────────────────────────
// flow: advisory lock → cooldown check → fetch repo metadata → insert scan → enqueue

export async function submitSingleScan(
  userId: string,
  repoOwner: string,
  repoName: string,
  encryptedAccessToken: string,
): Promise<SingleScanResult | CooldownError> {
  const accessToken = decrypt(encryptedAccessToken);

  // fetch repo metadata before the transaction — no point holding a lock
  // while waiting on a network call to GitHub
  const repo = await fetchGitHubRepo(repoOwner, repoName, accessToken);

  const txResult = await db.transaction(async (tx) => {
    return withAdvisoryLock(tx, 'scan_cooldown', String(repo.id), async () => {
      // check if the last terminal scan for this repo is within the cooldown window
      const [lastScan] = await tx
        .select({ updatedAt: scans.updatedAt })
        .from(scans)
        .where(
          sql`${scans.githubRepoId} = ${repo.id}
              AND ${scans.status} IN ('completed', 'cancelled')`,
        )
        .orderBy(desc(scans.updatedAt))
        .limit(1);

      if (lastScan) {
        const elapsed = Date.now() - lastScan.updatedAt.getTime();
        if (elapsed < COOLDOWN_MS) {
          const retryAfter = new Date(lastScan.updatedAt.getTime() + COOLDOWN_MS);
          return { type: 'cooldown' as const, retryAfter };
        }
      }

      // insert the scan row before enqueuing — the job references scanId,
      // so the row must exist before the worker can pick it up
      const [scan] = await tx
        .insert(scans)
        .values({
          requestedBy: userId,
          githubRepoId: repo.id,
          repoOwner: repo.owner.login,
          repoName: repo.name,
          isPrivate: repo.private,
          isFork: repo.fork,
          defaultBranch: repo.default_branch,
          language: repo.language,
          stars: repo.stargazers_count,
          sizeKb: repo.size,
          pushedAt: new Date(repo.pushed_at),
          status: 'queued',
        })
        .returning({ id: scans.id });

      if (!scan) throw new Error('failed to insert scan row');

      return { scanId: scan.id, repo };
    });
  });

  // cooldown hit — return early without touching Redis
  if ('type' in txResult && txResult.type === 'cooldown') {
    return txResult;
  }

  // enqueue AFTER the transaction commits so a rollback can't orphan a Redis job.
  // use scanId as jobId for stable status lookup.
  // use BullMQ deduplication with ttl aligned to cooldown.
  const { scanId, repo: txRepo } = txResult;
  const job = await scanQueue.add(
    'scan-repo',
    {
      scanId,
      repoOwner: txRepo.owner.login,
      repoName: txRepo.name,
      githubRepoId: txRepo.id,
      defaultBranch: txRepo.default_branch,
      sizeKb: txRepo.size,
    },
    {
      jobId: scanId,
      deduplication: { id: `repo-scan-${txRepo.id}`, ttl: COOLDOWN_MS },
    },
  );

  return { scanId, jobId: job.id! };
}

// ─── submitBatchScan ──────────────────────────────────────────────────────────
// flow: advisory lock → cooldown check → fetch all repos → insert batch row →
//       flowProducer.add() (parent + all children atomically)

export async function submitBatchScan(
  userId: string,
  type: 'user' | 'org',
  target: string,
  encryptedAccessToken: string,
): Promise<BatchScanResult | CooldownError> {
  const accessToken = decrypt(encryptedAccessToken);

  // fetch repos before the transaction — same reasoning as above,
  // this could take a few seconds for large orgs
  const repos = await fetchGitHubRepos(type, target, accessToken);

  if (repos.length === 0) {
    throw new Error(`No repositories found for ${type} "${target}"`);
  }

  const txResult = await db.transaction(async (tx) => {
    return withAdvisoryLock(tx, 'batch_cooldown', `${type}_${target}`, async () => {
      // batch cooldown scales with repo count:
      // scanning 100 repos locks that target for 300 hours (3h × 100).
      // this prevents hammering GitHub API and the scan queue with repeated bulk submissions.
      const [lastBatch] = await tx
        .select({ updatedAt: scanBatches.updatedAt, totalRepos: scanBatches.totalRepos })
        .from(scanBatches)
        .where(
          sql`${scanBatches.type} = ${type}
              AND ${scanBatches.target} = ${target}
              AND ${scanBatches.status} IN ('completed', 'cancelled')`,
        )
        .orderBy(desc(scanBatches.updatedAt))
        .limit(1);

      if (lastBatch) {
        const cooldownMs = COOLDOWN_MS * (lastBatch.totalRepos || 1);
        const elapsed = Date.now() - lastBatch.updatedAt.getTime();
        if (elapsed < cooldownMs) {
          const retryAfter = new Date(lastBatch.updatedAt.getTime() + cooldownMs);
          return { type: 'cooldown' as const, retryAfter };
        }
      }

      // insert the batch row first — child scan jobs reference batchId
      const [batch] = await tx
        .insert(scanBatches)
        .values({
          requestedBy: userId,
          type,
          target,
          status: 'queued',
          totalRepos: repos.length,
        })
        .returning({ id: scanBatches.id });

      if (!batch) throw new Error('failed to insert batch row');

      // insert all scan rows — we need their IDs to build the BullMQ child job data
      const scanRows = await tx
        .insert(scans)
        .values(
          repos.map((repo) => ({
            requestedBy: userId,
            batchId: batch.id,
            githubRepoId: repo.id,
            repoOwner: repo.owner.login,
            repoName: repo.name,
            isPrivate: repo.private,
            isFork: repo.fork,
            defaultBranch: repo.default_branch,
            language: repo.language,
            stars: repo.stargazers_count,
            sizeKb: repo.size,
            pushedAt: new Date(repo.pushed_at),
            status: 'queued' as const,
          })),
        )
        .returning({
          id: scans.id,
          githubRepoId: scans.githubRepoId,
          repoOwner: scans.repoOwner,
          repoName: scans.repoName,
          defaultBranch: scans.defaultBranch,
          sizeKb: scans.sizeKb,
        });

      return { batchId: batch.id, totalRepos: repos.length, scanRows };
    });
  });

  // cooldown hit — return early without touching Redis
  if ('type' in txResult && txResult.type === 'cooldown') {
    return txResult;
  }

  // enqueue AFTER the transaction commits so a rollback can't orphan Redis jobs.
  // flowProducer.add() creates the parent + all children atomically in Redis.
  // use scan row id as jobId and cooldown-aligned dedup keys by repo id.
  const { batchId, totalRepos, scanRows } = txResult;
  await flowProducer.add({
    name: 'batch-complete',
    queueName: 'scan-batches',
    data: { batchId },
    children: scanRows.map((scan) => ({
      name: 'scan-repo',
      queueName: 'github-scans',
      data: {
        scanId: scan.id,
        repoOwner: scan.repoOwner,
        repoName: scan.repoName,
        githubRepoId: scan.githubRepoId,
        defaultBranch: scan.defaultBranch,
        sizeKb: scan.sizeKb,
      },
      opts: {
        jobId: scan.id,
        deduplication: { id: `repo-scan-${scan.githubRepoId}`, ttl: COOLDOWN_MS },
      },
    })),
  });

  return { batchId, totalRepos };
}

// ─── getScanStatus ────────────────────────────────────────────────────────────
// checks Postgres first (fast, has full data for completed scans),
// falls back to BullMQ job state for in-flight scans (queued/in_progress).
// this two-phase approach avoids hitting Redis for every status poll
// once a scan is done — most polls will be for completed scans.

export async function getScanStatus(scanId: string): Promise<ScanStatusResult | null> {
  const [scan] = await db.select().from(scans).where(eq(scans.id, scanId)).limit(1);

  if (!scan) return null;

  // terminal states — all data is in Postgres, no need to check Redis
  if (['completed', 'failed', 'timeout', 'cancelled'].includes(scan.status)) {
    return { status: scan.status, score: scan.score, scan };
  }

  // for queued/in_progress, augment with live BullMQ job state
  // each scan uses scan.id as BullMQ jobId, so lookup is direct.
  // fall back gracefully if the job has already been cleaned up from Redis
  try {
    const job = await Job.fromId(scanQueue, scan.id);
    if (job) {
      const state = await job.getState();
      const progress = typeof job.progress === 'number' ? job.progress : undefined;
      return { status: state, score: null, progress, scan };
    }
  } catch {
    // job not in Redis yet or already cleaned up — return Postgres state as-is
  }

  return { status: scan.status, score: null, scan };
}
