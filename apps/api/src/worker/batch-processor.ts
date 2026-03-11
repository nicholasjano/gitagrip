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
    // Get all child job values
    const childrenValues = await job.getChildrenValues();
    const failedChildren = await job.getFailedChildrenValues();

    console.log(
      `Batch ${batchId}: ${Object.keys(childrenValues).length} completed, ${Object.keys(failedChildren).length} failed`,
    );

    // Get all scans for this batch that should count toward average
    const batchScans = await db
      .select({
        id: scans.id,
        score: scans.score,
        status: scans.status,
        is_private: scans.is_private,
        is_fork: scans.is_fork,
      })
      .from(scans)
      .where(eq(scans.batch_id, batchId));

    // Filter to qualifying scans (public, non-fork, completed)
    const qualifyingScans = batchScans.filter(
      (scan) =>
        scan.status === 'completed' &&
        scan.is_private === false &&
        scan.is_fork === false &&
        scan.score !== null,
    );

    console.log(`Batch ${batchId}: ${qualifyingScans.length} qualifying scans`);

    // Compute average score
    let averageScore: number | null = null;
    if (qualifyingScans.length > 0) {
      const sum = qualifyingScans.reduce((acc, scan) => acc + (scan.score || 0), 0);
      averageScore = Math.round(sum / qualifyingScans.length);
    }

    // Update batch
    await db
      .update(scanBatches)
      .set({
        status: 'completed',
        average_score: averageScore,
        completed_at: sql`NOW()`,
        updated_at: sql`NOW()`,
      })
      .where(eq(scanBatches.id, batchId));

    console.log(`Batch ${batchId} completed with average score ${averageScore}`);
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : 'Unknown error';

    // Update batch to failed
    await db
      .update(scanBatches)
      .set({
        status: 'failed',
        updated_at: sql`NOW()`,
      })
      .where(eq(scanBatches.id, batchId));

    console.error(`Batch ${batchId} failed:`, errorMessage);
    throw err;
  }
}
