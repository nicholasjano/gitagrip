import { scanQueue } from './queue/scan-queue.ts';
import { db } from './db/index.ts';
import { scans } from './db/schema.ts';

async function testWorker() {
  const githubRepoId = Math.floor(Math.random() * 1_000_000);

  console.log('Creating test scan in database...');

  const [scan] = await db
    .insert(scans)
    .values({
      githubRepoId,
      repoOwner: 'test-owner',
      repoName: 'test-repo',
      isPrivate: false,
      isFork: false,
      defaultBranch: 'main',
      language: 'TypeScript',
      stars: 100,
      sizeKb: 1000,
      status: 'queued',
      showOnLeaderboard: false,
    })
    .returning();

  console.log(`Created scan: ${scan.id} (githubRepoId: ${githubRepoId})`);
  console.log('Adding job to queue...');

  const job = await scanQueue.add('scan', {
    scanId: scan.id,
    repoOwner: 'test-owner',
    repoName: 'test-repo',
    githubRepoId,
  });

  console.log(`Job added: ${job.id}`);
  console.log('Now check your worker terminal...');

  await scanQueue.close();
  await db.$client.end();
  process.exit(0);
}

testWorker().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
