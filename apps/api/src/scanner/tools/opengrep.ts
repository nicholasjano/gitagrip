// opengrep runner and parser — security vulnerabilities, code quality, workflow security

import { readFile, rm } from 'fs/promises';
import path from 'path';
import { runTool } from '../run-tool.js';
import type { CategoryApplicability } from '../applicability.js';
import {
  clampScore,
  notApplicableScore,
  type CategoryScore,
  type ToolRunContext,
} from '../types.js';

const REPORT_DIR = '/tmp';

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

type OpengrepCategory = 'security_vulnerabilities' | 'code_quality' | 'workflow_security';

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

// Actions/workflow findings feed workflow_security (issue #15); other findings
// split by severity/CWE into security_vulnerabilities or code_quality.
// repo_security_posture has no Opengrep feeder — Scorecard owns that category.
function matchesWorkflowSecurity(result: OpengrepResult): boolean {
  const checkId = (result.check_id ?? '').toLowerCase();
  const filePath = (result.path ?? '').toLowerCase();

  if (checkId.startsWith('github-actions.') || checkId.includes('.github-actions.')) {
    return true;
  }
  if (filePath.includes('.github/workflows/')) {
    return true;
  }

  return false;
}

function classifyFinding(result: OpengrepResult): OpengrepCategory {
  if (matchesWorkflowSecurity(result)) return 'workflow_security';

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

function parseReport(raw: string): OpengrepReport {
  if (!raw.trim()) return {};
  const parsed = JSON.parse(raw) as OpengrepReport;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  return parsed;
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

  // code_quality bucket computed internally but not published — Lizard+jscpd own that category
  return [
    fail('security_vulnerabilities', applicability.security_vulnerabilities, 'N/A'),
    fail('workflow_security', applicability.workflow_security, 'N/A'),
  ];
}

export async function runOpengrep(
  ctx: ToolRunContext & { applicability: CategoryApplicability },
): Promise<CategoryScore[]> {
  const { repoDir, scanId, logger, signal, applicability } = ctx;
  const reportPath = path.join(REPORT_DIR, `opengrep-${scanId}.json`);

  try {
    const result = await runTool({
      cmd: 'opengrep',
      args: [
        'scan',
        '--json',
        '--output',
        reportPath,
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
    });

    if (result.status === 'timeout') {
      return buildFailureScores(applicability, 'opengrep timed out');
    }
    if (result.status === 'crash') {
      return buildFailureScores(applicability, 'opengrep crashed');
    }

    let report: OpengrepReport;
    try {
      const raw = await readFile(reportPath, 'utf8');
      report = parseReport(raw);
    } catch {
      return buildFailureScores(applicability, 'opengrep JSON parse error');
    }

    const buckets: Record<OpengrepCategory, SeverityBucket> = {
      security_vulnerabilities: emptyBucket(),
      code_quality: emptyBucket(),
      workflow_security: emptyBucket(),
    };

    for (const finding of report.results ?? []) {
      const category = classifyFinding(finding);
      const severity = normalizeSeverity(finding.extra?.severity);
      buckets[category][severity]++;
    }

    // code_quality bucket kept in buckets for future re-enable; not pushed to categoryScores[]
    void buckets.code_quality;

    return [
      buildCategoryScore(
        'security_vulnerabilities',
        buckets.security_vulnerabilities,
        applicability.security_vulnerabilities,
        'N/A',
      ),
      buildCategoryScore(
        'workflow_security',
        buckets.workflow_security,
        applicability.workflow_security,
        'No GitHub Actions workflows detected',
      ),
    ];
  } finally {
    await rm(reportPath, { force: true });
  }
}
