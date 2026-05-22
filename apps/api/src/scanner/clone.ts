// runs git clone on a repo and saves the clone to a temporary directory, exports cloneRepo for scan-processor.ts

import { execFile as execFileCb } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import fs from 'fs/promises';
import { UnrecoverableError } from 'bullmq';
import { db } from '../db/index.js';
import { scans } from '../db/schema.js';
import { eq } from 'drizzle-orm';
import { createScanLogger, type ScanLogger } from './logger.js';

const execFile = promisify(execFileCb);

// 2 gb limit
const MAX_REPO_SIZE_KB = 2_097_152;
const MAX_CLONE_SIZE_BYTES = MAX_REPO_SIZE_KB * 1024;
const CLONE_TIMEOUT_MS = 120_000;
// 5 gb minimum free space on /tmp before we attempt a clone
const MIN_FREE_DISK_BYTES = 5 * 1024 * 1024 * 1024;

// only allow safe characters in owner/repo names before interpolating into the url
const SAFE_NAME = /^[a-zA-Z0-9._-]+$/;
const SAFE_BRANCH = /^(?!-)[A-Za-z0-9._/-]{1,255}$/;

export async function cloneRepo(
  repoOwner: string,
  repoName: string,
  scanId: string,
  defaultBranch: string,
  sizeKb: number,
  signal?: AbortSignal,
): Promise<string> {
  const logger = createScanLogger(scanId);

  if (!SAFE_NAME.test(repoOwner) || !SAFE_NAME.test(repoName)) {
    throw new UnrecoverableError(`Invalid repo owner or name: ${repoOwner}/${repoName}`);
  }
  if (!SAFE_BRANCH.test(defaultBranch)) {
    throw new UnrecoverableError(`Invalid default branch for ${repoOwner}/${repoName}`);
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
    logger.warn('clone', 'large repo warning', { repoOwner, repoName, sizeKb });
  }

  // check available disk space on /tmp before cloning
  const { bavail, bsize } = await fs.statfs('/tmp');
  const freeDiskBytes = bavail * bsize;

  if (freeDiskBytes < MIN_FREE_DISK_BYTES) {
    logger.error('clone', 'insufficient disk space', { freeDiskBytes });
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
        '-c',
        'core.symlinks=false',
        '--depth=1',
        '--single-branch',
        `--branch=${defaultBranch}`,
        '--quiet',
        '--no-recurse-submodules',
        cloneUrl,
        destDir,
      ],
      { timeout: CLONE_TIMEOUT_MS, signal },
    );
  } catch (err: unknown) {
    const e = err as {
      killed?: boolean;
      code?: number | string;
      stderr?: string;
      message?: string;
    };

    if (e.killed) {
      throw new Error(
        `Clone timed out after ${CLONE_TIMEOUT_MS / 1000}s for ${repoOwner}/${repoName}`,
        { cause: err },
      );
    }

    // git binary not installed — code is the string 'ENOENT', not a number
    if (e.code === 'ENOENT') {
      throw new Error('git is not installed or not in PATH', { cause: err });
    }

    // git fatal errors all exit 128 — parse stderr for specific failure reason.
    // more specific checks first since e.g. "remote branch not found" also contains "not found"
    if (e.code === 128) {
      const stderr = (e.stderr ?? '').toLowerCase();

      if (stderr.includes('remote branch') && stderr.includes('not found')) {
        throw new UnrecoverableError(
          `Branch '${defaultBranch}' not found in ${repoOwner}/${repoName}`,
        );
      }
      if (stderr.includes('authentication') || stderr.includes('could not read username')) {
        throw new UnrecoverableError(`Authentication failed for ${repoOwner}/${repoName}`);
      }
      if (stderr.includes('not found') || stderr.includes('does not exist')) {
        throw new UnrecoverableError(`Repository not found: ${repoOwner}/${repoName}`);
      }
    }

    throw new Error(`Clone failed for ${repoOwner}/${repoName}: ${e.message}`, { cause: err });
  }

  await removeSymlinks(destDir, logger);

  const actualCloneSizeBytes = await getDirectorySizeBytes(destDir);
  if (actualCloneSizeBytes > MAX_CLONE_SIZE_BYTES) {
    await db
      .update(scans)
      .set({ status: 'failed', errorMessage: 'Repository exceeds 2 GB checked-out size limit' })
      .where(eq(scans.id, scanId));
    throw new UnrecoverableError('Repository exceeds 2 GB checked-out size limit');
  }

  return destDir;
}

// defense-in-depth: walk the tree manually with opendir + lstat so we never
// follow directory symlinks (fs.readdir recursive does). core.symlinks=false
// already prevents real symlinks, but a post-clone sweep catches edge cases.
async function removeSymlinks(dirPath: string, logger: ScanLogger): Promise<void> {
  let removed = 0;

  async function walk(dir: string): Promise<void> {
    let handle;
    try {
      handle = await fs.opendir(dir);
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw err;
    }

    try {
      for await (const entry of handle) {
        if (entry.name === '.git') continue;

        const fullPath = path.join(dir, entry.name);
        let stats;
        try {
          stats = await fs.lstat(fullPath);
        } catch (err: unknown) {
          if ((err as NodeJS.ErrnoException).code === 'ENOENT') continue;
          throw err;
        }

        if (stats.isSymbolicLink()) {
          try {
            await fs.unlink(fullPath);
            removed++;
          } catch (err: unknown) {
            if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
          }
        } else if (stats.isDirectory()) {
          await walk(fullPath);
        }
      }
    } finally {
      // opendir handle is auto-closed by the for-await loop, but if we
      // break out early due to an error the finally ensures cleanup
    }
  }

  await walk(dirPath);

  if (removed > 0) {
    logger.warn('clone', 'removed symlinks', { dirPath, count: removed });
  }
}

async function getDirectorySizeBytes(dirPath: string): Promise<number> {
  let totalBytes = 0;

  async function walk(dir: string): Promise<void> {
    let handle;
    try {
      handle = await fs.opendir(dir);
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw err;
    }

    try {
      for await (const entry of handle) {
        const fullPath = path.join(dir, entry.name);
        let stats;
        try {
          stats = await fs.lstat(fullPath);
        } catch (err: unknown) {
          if ((err as NodeJS.ErrnoException).code === 'ENOENT') continue;
          throw err;
        }

        if (stats.isSymbolicLink()) continue;
        if (stats.isDirectory()) {
          await walk(fullPath);
          continue;
        }
        if (stats.isFile()) {
          totalBytes += stats.size;
          if (totalBytes > MAX_CLONE_SIZE_BYTES) return;
        }
      }
    } finally {
      // opendir handle is auto-closed by the for-await loop
    }
  }

  await walk(dirPath);
  return totalBytes;
}
