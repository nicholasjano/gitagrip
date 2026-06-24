// lizard runner and parser — cyclomatic complexity partial score for code_quality

import { parse } from 'csv-parse/sync';
import { runTool } from '../run-tool.js';
import { clampScore, type PartialToolScore, type ToolRunContext } from '../types.js';

const EXCLUSIONS = [
  './node_modules/*',
  './vendor/*',
  './.git/*',
  './dist/*',
  './.next/*',
  './build/*',
  './target/*',
];

interface LizardRow {
  CCN?: string;
}

function failedPartial(reason: string): PartialToolScore {
  return { score: 0, detail: '', failed: true, failureReason: reason };
}

function scoreComplexity(avgCcn: number, pctAbove15: number, maxCcn: number): number {
  let score = 100;

  if (avgCcn > 15) score -= 30;
  else if (avgCcn >= 10) score -= 15;

  if (pctAbove15 > 20) score -= 20;
  if (maxCcn > 40) score -= 10;

  return clampScore(score);
}

function parseCsv(
  stdout: string,
): { avgCcn: number; pctAbove15: number; pctAbove25: number; maxCcn: number } | null {
  if (!stdout.trim()) {
    return { avgCcn: 0, pctAbove15: 0, pctAbove25: 0, maxCcn: 0 };
  }

  const rows = parse(stdout, {
    columns: true,
    skip_empty_lines: true,
    relax_column_count: true,
  }) as LizardRow[];

  const ccnValues: number[] = [];
  for (const row of rows) {
    const ccn = Number(row.CCN);
    if (!Number.isFinite(ccn)) continue;
    ccnValues.push(ccn);
  }

  if (ccnValues.length === 0) {
    return { avgCcn: 0, pctAbove15: 0, pctAbove25: 0, maxCcn: 0 };
  }

  const sum = ccnValues.reduce((acc, v) => acc + v, 0);
  const above15 = ccnValues.filter((v) => v > 15).length;
  const above25 = ccnValues.filter((v) => v > 25).length;

  return {
    avgCcn: sum / ccnValues.length,
    pctAbove15: (above15 / ccnValues.length) * 100,
    pctAbove25: (above25 / ccnValues.length) * 100,
    maxCcn: Math.max(...ccnValues),
  };
}

export async function runLizard(ctx: ToolRunContext): Promise<PartialToolScore> {
  const { repoDir, logger, signal } = ctx;

  const args = [
    '.',
    ...EXCLUSIONS.flatMap((pattern) => ['-x', pattern]),
    '--csv',
    '-t',
    '2',
    '-i',
    '-1',
  ];

  try {
    const result = await runTool({
      cmd: 'lizard',
      args,
      cwd: repoDir,
      label: 'lizard',
      logger,
      signal,
    });

    if (result.status === 'timeout') return failedPartial('lizard timed out');
    if (result.status === 'crash') return failedPartial('lizard crashed');

    const stats = parseCsv(result.stdout);
    if (!stats) return failedPartial('lizard CSV parse error');

    const score = scoreComplexity(stats.avgCcn, stats.pctAbove15, stats.maxCcn);
    const avgLabel = stats.avgCcn.toFixed(1);
    const above25Label = stats.pctAbove25.toFixed(1);

    return {
      score,
      detail: `Avg complexity: ${avgLabel} CCN, ${above25Label}% functions > 25 CCN`,
      failed: false,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'lizard parse error';
    logger.error('tool', 'lizard parser failed', { error: message });
    return failedPartial(message);
  }
}
