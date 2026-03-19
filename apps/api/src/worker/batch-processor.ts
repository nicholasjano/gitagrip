// for batch scans, runs parent job only after all child jobs are completed and collects all children scores

import type { Job } from 'bullmq';
import { eq, sql } from 'drizzle-orm';
import { db } from '../db/index.ts';
import { scanBatches, scans } from '../db/schema.ts';

interface BatchJobData {
  batchId: string;
}

export default async function batchProcessor(job: Job<BatchJobData>) {
  const { batchId } = job.data;

  console.log(`Processing batch ${batchId}`);

  try {
    // get all processed child values
    const childrenValues = await job.getChildrenValues();
    console.log(`Batch ${batchId}: ${Object.keys(childrenValues).length} children processed`);

    // get all scans for this batch and derive counters from postgres
    const batchScans = await db
      .select({
        id: scans.id,
        score: scans.score,
        status: scans.status,
        isPrivate: scans.isPrivate,
        isFork: scans.isFork,
      })
      .from(scans)
      .where(eq(scans.batchId, batchId));

    // filter to qualifying scans (public, non-fork, completed)
    const qualifyingScans = batchScans.filter(
      (scan) =>
        scan.status === 'completed' &&
        scan.isPrivate === false &&
        scan.isFork === false &&
        scan.score !== null,
    );
    const completedRepos = batchScans.filter((scan) => scan.status === 'completed').length;

    console.log(`Batch ${batchId}: ${qualifyingScans.length} qualifying scans`);

    // compute average score
    let averageScore: number | null = null;
    if (qualifyingScans.length > 0) {
      const sum = qualifyingScans.reduce((acc, scan) => acc + (scan.score || 0), 0);
      averageScore = Math.round(sum / qualifyingScans.length);
    }

    // update batch
    await db
      .update(scanBatches)
      .set({
        status: 'completed',
        averageScore: averageScore?.toString() ?? null,
        completedRepos,
        completedAt: sql`NOW()`,
        updatedAt: sql`NOW()`,
      })
      .where(eq(scanBatches.id, batchId));

    console.log(`Batch ${batchId} completed with average score ${averageScore}`);
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : 'Unknown error';

    // update batch to failed
    await db
      .update(scanBatches)
      .set({
        status: 'failed',
        updatedAt: sql`NOW()`,
      })
      .where(eq(scanBatches.id, batchId));

    console.error(`Batch ${batchId} failed:`, errorMessage);
    throw err;
  }
}
