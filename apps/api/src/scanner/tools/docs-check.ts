// pure Node.js documentation standards scorer

import { readFile, readdir } from 'fs/promises';
import path from 'path';
import type { FileManifest } from '../detect-files.js';
import { clampScore, type CategoryScore, type ToolRunContext } from '../types.js';

async function findRootReadme(repoDir: string): Promise<string | null> {
  const entries = await readdir(repoDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (/^readme(\..+)?$/i.test(entry.name)) {
      return path.join(repoDir, entry.name);
    }
  }
  return null;
}

function scoreReadmeQuality(content: string): { points: number; signals: string[] } {
  const signals: string[] = [];
  let points = 0;

  if (content.length > 500) {
    points += 5;
    signals.push('substantial length');
  }
  if (/^#{1,6}\s/m.test(content)) {
    points += 5;
    signals.push('has headings');
  }
  if (/```/.test(content)) {
    points += 5;
    signals.push('has code blocks');
  }

  return { points, signals };
}

export async function runDocsCheck(
  ctx: ToolRunContext & { manifest: FileManifest },
): Promise<CategoryScore[]> {
  const { repoDir, manifest } = ctx;

  let score = 0;
  const present: string[] = [];

  if (manifest.hasReadme) {
    score += 25;
    present.push('README');
  }
  if (manifest.hasLicense) {
    score += 20;
    present.push('LICENSE');
  }
  if (manifest.hasContributing) {
    score += 10;
    present.push('CONTRIBUTING');
  }
  if (manifest.hasChangelog) {
    score += 10;
    present.push('CHANGELOG');
  }
  if (manifest.hasCodeOfConduct) {
    score += 5;
    present.push('CODE_OF_CONDUCT');
  }
  if (manifest.hasSecurityPolicy) {
    score += 15;
    present.push('SECURITY');
  }

  const qualitySignals: string[] = [];
  if (manifest.hasReadme) {
    try {
      const readmePath = await findRootReadme(repoDir);
      if (readmePath) {
        const content = await readFile(readmePath, 'utf8');
        const quality = scoreReadmeQuality(content);
        score += quality.points;
        qualitySignals.push(...quality.signals);
      }
    } catch {
      // existence points already awarded from manifest
    }
  }

  const parts: string[] = [];
  if (present.length > 0) parts.push(`Found: ${present.join(', ')}`);
  if (qualitySignals.length > 0) parts.push(`README quality: ${qualitySignals.join(', ')}`);

  return [
    {
      category: 'documentation_standards',
      score: clampScore(score),
      applicable: true,
      message: parts.length > 0 ? parts.join('; ') : 'No documentation files detected',
      findingCount: present.length,
    },
  ];
}
