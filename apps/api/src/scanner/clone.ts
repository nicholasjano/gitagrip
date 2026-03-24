// runs git clone on a repo and saves the clone to a temporary directory, exports cloneRepo for scan-processor.ts

import { execFile as execFileCb } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import { UnrecoverableError } from 'bullmq';
import { db } from '../db/index.js';
import { scans } from '../db/schema.js';
import { eq } from 'drizzle-orm';

const execFile = promisify(execFileCb);

// 2 gb limit
const MAX_REPO_SIZE_KB = 2_097_152;
const CLONE_TIMEOUT_MS = 120_000;
// 5 gb minimum free space on /tmp before we attempt a clone
const MIN_FREE_DISK_BYTES = 5 * 1024 * 1024 * 1024;

// only allow safe characters in owner/repo names before interpolating into the url
const SAFE_NAME = /^[a-zA-Z0-9._-]+$/;

export async function cloneRepo(
  repoOwner: string,
  repoName: string,
  scanId: string,
  defaultBranch: string,
  sizeKb: number,
): Promise<string> {
  if (!SAFE_NAME.test(repoOwner) || !SAFE_NAME.test(repoName)) {
    throw new UnrecoverableError(`Invalid repo owner or name: ${repoOwner}/${repoName}`);
  }

  // check size before we even attempt the clone
  if (sizeKb > MAX_REPO_SIZE_KB) {
    await db
      .update(scans)
      .set({ status: 'failed', errorMessage: 'Repository exceeds 2 GB size limit' })
      .where(eq(scans.id, scanId));
    throw new UnrecoverableError('Repository exceeds 2 GB size limit');
  }

  if (sizeKb > 512_000) {
    console.warn(
      `[clone] large repo warning: ${repoOwner}/${repoName} is ${Math.round(sizeKb / 1024)} MB`,
    );
  }

  // check available disk space on /tmp before cloning
  const { bavail, bsize } = await fs.statfs('/tmp');
  const freeDiskBytes = bavail * bsize;

  if (freeDiskBytes < MIN_FREE_DISK_BYTES) {
    console.error(
      `[clone] insufficient disk space: ${Math.round((freeDiskBytes / 1024 / 1024 / 1024) * 10) / 10} GB free`,
    );
    await db
      .update(scans)
      .set({ status: 'failed', errorMessage: 'Insufficient disk space' })
      .where(eq(scans.id, scanId));
    throw new UnrecoverableError('Insufficient disk space');
  }

  const cloneUrl = `https://github.com/${repoOwner}/${repoName}.git`;
  const destDir = `/tmp/gitagrip-scan-${scanId}`;

  try {
    await execFile(
      'git',
      [
        'clone',
        '--depth=1',
        '--single-branch',
        `--branch=${defaultBranch}`,
        '--quiet',
        '--no-recurse-submodules',
        cloneUrl,
        destDir,
      ],
      { timeout: CLONE_TIMEOUT_MS },
    );
  } catch (err: unknown) {
    const e = err as { killed?: boolean; code?: number | string; message?: string };

    if (e.killed) {
      throw new Error(
        `Clone timed out after ${CLONE_TIMEOUT_MS / 1000}s for ${repoOwner}/${repoName}`,
        { cause: err },
      );
    }

    if (e.code === 128) {
      throw new UnrecoverableError(`Repository not found: ${repoOwner}/${repoName}`);
    }

    throw new Error(`Clone failed for ${repoOwner}/${repoName}: ${e.message}`, { cause: err });
  }

  await removeSymlinks(destDir);

  return destDir;
}

// symlinks in a cloned repo can point anywhere on the host filesystem.
// tools like trivy and opengrep follow them by default, so we remove them upfront.
async function removeSymlinks(dirPath: string): Promise<void> {
  const entries = await fs.readdir(dirPath, { recursive: true });
  let removed = 0;

  for (const entry of entries) {
    const fullPath = `${dirPath}/${entry}`;
    const stat = await fs.lstat(fullPath);
    if (stat.isSymbolicLink()) {
      await fs.unlink(fullPath);
      removed++;
    }
  }

  if (removed > 0) {
    console.warn(`[clone] removed ${removed} symlink(s) from ${dirPath}`);
  }
}
