// opengrep runner and parser — security, code quality, repo posture categories

import { runTool } from '../run-tool.js';
import type { CategoryApplicability } from '../applicability.js';
import {
  clampScore,
  notApplicableScore,
  type CategoryScore,
  type ToolRunContext,
} from '../types.js';

interface OpengrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  extra?: {
    severity?: string;
    message?: string;
    metadata?: { cwe?: string[] };
  };
}

interface OpengrepReport {
  results?: OpengrepResult[];
}

type OpengrepCategory = 'security_vulnerabilities' | 'code_quality' | 'repo_security_posture';

interface SeverityBucket {
  error: number;
  warning: number;
  info: number;
}

function emptyBucket(): SeverityBucket {
  return { error: 0, warning: 0, info: 0 };
}

function normalizeSeverity(value?: string): keyof SeverityBucket {
  const upper = (value ?? 'INFO').toUpperCase();
  if (upper === 'ERROR') return 'error';
  if (upper === 'WARNING') return 'warning';
  return 'info';
}

function matchesRepoPosture(result: OpengrepResult): boolean {
  const haystack = [result.check_id ?? '', result.path ?? '', result.extra?.message ?? '']
    .join(' ')
    .toLowerCase();

  return (
    haystack.includes('github-actions') ||
    haystack.includes('secrets') ||
    haystack.includes('hardcoded')
  );
}

function classifyFinding(result: OpengrepResult): OpengrepCategory {
  if (matchesRepoPosture(result)) return 'repo_security_posture';

  const cwe = result.extra?.metadata?.cwe ?? [];
  const severity = normalizeSeverity(result.extra?.severity);

  if (severity === 'error' || cwe.length > 0) return 'security_vulnerabilities';
  if (severity === 'warning') return 'code_quality';
  return 'code_quality';
}

function scoreBucket(bucket: SeverityBucket): number {
  return clampScore(100 - (bucket.error * 10 + bucket.warning * 3 + bucket.info * 1));
}

function buildCategoryScore(
  category: OpengrepCategory,
  bucket: SeverityBucket,
  applicable: boolean,
  naReason: string,
): CategoryScore {
  if (!applicable) {
    return notApplicableScore(category, naReason);
  }

  const total = bucket.error + bucket.warning + bucket.info;
  return {
    category,
    score: scoreBucket(bucket),
    applicable: true,
    message: total === 0 ? 'No findings detected' : `${total} finding(s) detected`,
    findingCount: total,
  };
}

function parseReport(stdout: string): OpengrepReport {
  if (!stdout.trim()) return {};
  return JSON.parse(stdout) as OpengrepReport;
}

function buildFailureScores(applicability: CategoryApplicability, reason: string): CategoryScore[] {
  const fail = (
    category: OpengrepCategory,
    applicable: boolean,
    naReason: string,
  ): CategoryScore =>
    applicable
      ? { category, score: 0, applicable: true, message: `Tool failed: ${reason}`, findingCount: 0 }
      : notApplicableScore(category, naReason);

  return [
    fail('security_vulnerabilities', applicability.security_vulnerabilities, 'N/A'),
    fail('code_quality', applicability.code_quality, 'No supported source files detected'),
    fail('repo_security_posture', applicability.repo_security_posture, 'N/A'),
  ];
}

export async function runOpengrep(
  ctx: ToolRunContext & { applicability: CategoryApplicability },
): Promise<CategoryScore[]> {
  const { repoDir, logger, signal, applicability } = ctx;

  const result = await runTool({
    cmd: 'opengrep',
    args: [
      'scan',
      '--json',
      '-f',
      '/opt/opengrep-rules/',
      '-j',
      '2',
      '--timeout-threshold',
      '3',
      repoDir,
    ],
    label: 'opengrep',
    logger,
    signal,
    maxBuffer: 50 * 1024 * 1024,
    expectedExitCodes: [1],
  });

  if (result.status === 'timeout') {
    return buildFailureScores(applicability, 'opengrep timed out');
  }
  if (result.status === 'crash') {
    return buildFailureScores(applicability, 'opengrep crashed');
  }

  let report: OpengrepReport;
  try {
    report = parseReport(result.stdout);
  } catch {
    return buildFailureScores(applicability, 'opengrep JSON parse error');
  }

  const buckets: Record<OpengrepCategory, SeverityBucket> = {
    security_vulnerabilities: emptyBucket(),
    code_quality: emptyBucket(),
    repo_security_posture: emptyBucket(),
  };

  for (const finding of report.results ?? []) {
    const category = classifyFinding(finding);
    const severity = normalizeSeverity(finding.extra?.severity);
    buckets[category][severity]++;
  }

  return [
    buildCategoryScore(
      'security_vulnerabilities',
      buckets.security_vulnerabilities,
      applicability.security_vulnerabilities,
      'N/A',
    ),
    buildCategoryScore(
      'code_quality',
      buckets.code_quality,
      applicability.code_quality,
      'No supported source files detected',
    ),
    buildCategoryScore(
      'repo_security_posture',
      buckets.repo_security_posture,
      applicability.repo_security_posture,
      'N/A',
    ),
  ];
}
