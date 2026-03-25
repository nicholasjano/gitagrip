// exports cleanupRepo for scan-processor.ts

import fs from 'fs/promises';

const SCAN_DIR_PREFIX = '/tmp/gitagrip-scan-';

export async function cleanupRepo(dirPath: string): Promise<void> {
  if (!dirPath.startsWith(SCAN_DIR_PREFIX)) {
    console.warn(`cleanup refused: path is outside allowed prefix — ${dirPath}`);
    return;
  }

  await fs.rm(dirPath, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}
