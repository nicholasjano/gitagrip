// scan submission and retrieval routes
// routes stay thin — all business logic lives in scan-service.ts

import { Router } from 'express';
import { eq } from 'drizzle-orm';
import { db } from '../db/index.js';
import { scans, scanCategories, scanBatches } from '../db/schema.js';
import { requireAuth, optionalAuth } from '../middleware/auth.js';
import {
  scanSubmitLimiter,
  batchSubmitLimiter,
  scanStatusLimiter,
} from '../middleware/scan-rate-limit.js';
import { submitSingleScan, submitBatchScan, getScanStatus } from '../services/scan-service.js';

const router = Router();

// ─── POST /scans ──────────────────────────────────────────────────────────────
// submit a single repo scan.
// fetches live repo metadata from GitHub, inserts scan row, enqueues job.

router.post('/', requireAuth, scanSubmitLimiter, async (req, res) => {
  const { repoOwner, repoName } = req.body as { repoOwner?: string; repoName?: string };

  if (!repoOwner || !repoName) {
    res.status(400).json({ error: 'repoOwner and repoName are required' });
    return;
  }

  try {
    const result = await submitSingleScan(req.user!.id, repoOwner, repoName, req.user!.accessToken);

    if ('type' in result && result.type === 'cooldown') {
      res.status(429).json({
        error: 'This repository was scanned recently. Please wait before scanning again.',
        retryAfter: result.retryAfter.toISOString(),
      });
      return;
    }

    res.status(202).json({ scanId: result.scanId, status: 'queued' });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to submit scan';
    const pgErr = err as {
      code?: string;
      constraint?: string;
      cause?: { code?: string; constraint?: string };
    };
    const dbCode = pgErr.code ?? pgErr.cause?.code;
    const dbConstraint = pgErr.constraint ?? pgErr.cause?.constraint;
    // surface GitHub 404s and rate limit errors cleanly
    if (message.includes('not found')) {
      res.status(404).json({ error: message });
      return;
    }
    if (message.includes('rate limit')) {
      res.status(503).json({ error: message });
      return;
    }
    if (dbCode === '23505' && dbConstraint === 'idx_one_active_scan_per_repo') {
      res.status(409).json({
        error: 'A scan for this repository is already queued or in progress.',
      });
      return;
    }
    console.error('Scan submission error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── POST /scans/batch ────────────────────────────────────────────────────────
// submit a batch scan for all repos belonging to a GitHub user or org.

router.post('/batch', requireAuth, batchSubmitLimiter, async (req, res) => {
  const { type, target } = req.body as { type?: string; target?: string };

  if (!type || !target) {
    res.status(400).json({ error: 'type and target are required' });
    return;
  }

  if (type !== 'user' && type !== 'org') {
    res.status(400).json({ error: 'type must be "user" or "org"' });
    return;
  }

  try {
    const result = await submitBatchScan(req.user!.id, type, target, req.user!.accessToken);

    if ('type' in result && result.type === 'cooldown') {
      res.status(429).json({
        error: 'This user/org was scanned recently. Cooldown scales with repo count.',
        retryAfter: result.retryAfter.toISOString(),
      });
      return;
    }

    res.status(202).json({
      batchId: result.batchId,
      status: 'queued',
      totalRepos: result.totalRepos,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to submit batch scan';
    if (message.includes('not found')) {
      res.status(404).json({ error: message });
      return;
    }
    if (message.includes('rate limit')) {
      res.status(503).json({ error: message });
      return;
    }
    if (message.includes('No repositories found')) {
      res.status(422).json({ error: message });
      return;
    }
    console.error('Batch submission error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── GET /scans/:id ───────────────────────────────────────────────────────────
// full scan result including all 13 category scores.
// public — scan results are visible without auth.

router.get('/:id', optionalAuth, async (req, res) => {
  const { id } = req.params;

  try {
    const [scan] = await db.select().from(scans).where(eq(scans.id, id)).limit(1);

    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    const categories = await db.select().from(scanCategories).where(eq(scanCategories.scanId, id));

    res.json({ scan, categories });
  } catch (err) {
    console.error('Get scan error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── GET /scans/:id/status ────────────────────────────────────────────────────
// lightweight status poll — used by the frontend while a scan is in progress.
// checks Postgres first, falls back to BullMQ job state for in-flight scans.

router.get('/:id/status', optionalAuth, scanStatusLimiter, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await getScanStatus(id);

    if (!result) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }

    res.json({
      status: result.status,
      ...(result.score != null && { score: result.score }),
      ...(result.progress != null && { progress: result.progress }),
    });
  } catch (err) {
    console.error('Get scan status error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── GET /batches/:id ─────────────────────────────────────────────────────────
// batch status with all child scan summaries.
// note: registered under /batches in app.ts, not /scans — different router mount point.

export const batchRouter = Router();

batchRouter.get('/:id', requireAuth, async (req, res) => {
  const { id } = req.params;

  try {
    const [batch] = await db.select().from(scanBatches).where(eq(scanBatches.id, id)).limit(1);

    if (!batch) {
      res.status(404).json({ error: 'Batch not found' });
      return;
    }

    // only let the batch owner see it
    if (batch.requestedBy !== req.user!.id) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    const batchScans = await db
      .select({
        id: scans.id,
        repoOwner: scans.repoOwner,
        repoName: scans.repoName,
        status: scans.status,
        score: scans.score,
        isPrivate: scans.isPrivate,
        isFork: scans.isFork,
        completedAt: scans.completedAt,
      })
      .from(scans)
      .where(eq(scans.batchId, id));

    res.json({ batch, scans: batchScans });
  } catch (err) {
    console.error('Get batch error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
