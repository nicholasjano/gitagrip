// resolves THIRD-PARTY-NOTICES.md across local dev and docker runtime paths

import { access, readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const moduleDir = path.dirname(fileURLToPath(import.meta.url));

const NOTICE_CANDIDATES = [
  ...(process.env.NOTICES_PATH ? [path.resolve(process.env.NOTICES_PATH)] : []),
  path.resolve(process.cwd(), 'THIRD-PARTY-NOTICES.md'),
  path.resolve(process.cwd(), '../../THIRD-PARTY-NOTICES.md'),
  path.resolve(moduleDir, '../../../THIRD-PARTY-NOTICES.md'),
  path.resolve(moduleDir, '../../../../THIRD-PARTY-NOTICES.md'),
];

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

export async function resolveThirdPartyNoticesPath(): Promise<string | null> {
  for (const candidate of NOTICE_CANDIDATES) {
    if (await exists(candidate)) return candidate;
  }
  return null;
}

export async function readThirdPartyNotices(): Promise<string> {
  const noticesPath = await resolveThirdPartyNoticesPath();
  if (!noticesPath) {
    throw new Error('THIRD-PARTY-NOTICES.md not found');
  }
  return readFile(noticesPath, 'utf8');
}
