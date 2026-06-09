// jscpd runner and parser — duplication partial score for code_quality

import { readFile, rm } from 'fs/promises';
import path from 'path';
import { runTool } from '../run-tool.js';
import { clampScore, type PartialToolScore, type ToolRunContext } from '../types.js';

const REPORT_DIR = '/tmp';

interface JscpdStatistic {
  percentage?: number;
  clones?: number;
  duplicatedLines?: number;
}

interface JscpdReport {
  statistics?: {
    total?: JscpdStatistic;
  };
}

function failedPartial(reason: string): PartialToolScore {
  return { score: 0, detail: '', failed: true, failureReason: reason };
}

function scoreDuplication(percentage: number): number {
  if (percentage < 3) return 100;
  if (percentage < 5) return 90;
  if (percentage < 10) return 75;
  if (percentage < 20) return 50;
  return 20;
}

async function parseReport(reportPath: string): Promise<JscpdStatistic | null> {
  const raw = await readFile(reportPath, 'utf8');
  if (!raw.trim()) return { percentage: 0, clones: 0, duplicatedLines: 0 };

  const parsed = JSON.parse(raw) as JscpdReport;
  return parsed.statistics?.total ?? { percentage: 0, clones: 0, duplicatedLines: 0 };
}

export async function runJscpd(ctx: ToolRunContext): Promise<PartialToolScore> {
  const { repoDir, scanId, logger, signal } = ctx;
  const outputDir = path.join(REPORT_DIR, `jscpd-${scanId}`);
  const reportPath = path.join(outputDir, 'jscpd-report.json');

  try {
    const result = await runTool({
      cmd: 'jscpd',
      args: [
        repoDir,
        '--reporters',
        'json',
        '--output',
        outputDir,
        '--ignore',
        '**/node_modules/**,**/.git/**,**/vendor/**,**/dist/**',
        '--gitignore',
        '--silent',
      ],
      label: 'jscpd',
      logger,
      signal,
    });

    if (result.status === 'timeout') return failedPartial('jscpd timed out');
    if (result.status === 'crash') return failedPartial('jscpd crashed');

    let stats: JscpdStatistic | null;
    try {
      stats = await parseReport(reportPath);
    } catch {
      return failedPartial('jscpd JSON parse error');
    }

    if (!stats) return failedPartial('jscpd JSON parse error');

    const percentage = stats.percentage ?? 0;
    const clones = stats.clones ?? 0;
    const score = clampScore(scoreDuplication(percentage));

    return {
      score,
      detail: `${percentage.toFixed(1)}% duplication (${clones} clones)`,
      failed: false,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'jscpd parse error';
    logger.error('tool', 'jscpd parser failed', { error: message });
    return failedPartial(message);
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
}
