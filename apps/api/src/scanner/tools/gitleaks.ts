// gitleaks runner and parser — maps to exposed_secrets

import { readFile, rm } from 'fs/promises';
import path from 'path';
import { runTool } from '../run-tool.js';
import { clampScore, toolFailedScores, type CategoryScore, type ToolRunContext } from '../types.js';

const REPORT_DIR = '/tmp';

interface GitleaksFinding {
  RuleID?: string;
  File?: string;
  StartLine?: number;
  Match?: string;
  Entropy?: number;
}

type SecretSeverity = 'critical' | 'high' | 'medium' | 'low';

const CRITICAL_RULES = new Set(['private-key', 'aws-access-key', 'gcp-api-key', 'github-pat']);

const HIGH_RULES = new Set(['generic-api-key', 'slack-token', 'stripe-api-key']);

const MEDIUM_RULES = new Set(['generic-password', 'jwt']);

const LOW_RULES = new Set(['mailchimp-api-key']);

function classifyRule(ruleId: string, entropy?: number): SecretSeverity {
  const normalized = ruleId.toLowerCase();

  if (CRITICAL_RULES.has(normalized)) return 'critical';
  if (HIGH_RULES.has(normalized)) return 'high';
  if (MEDIUM_RULES.has(normalized)) return 'medium';
  if (LOW_RULES.has(normalized)) return 'low';

  if (normalized.includes('.env') || normalized.includes('env-file')) return 'low';
  if (normalized.includes('generic') && (entropy ?? 0) >= 4.5) return 'medium';

  return 'medium';
}

function scoreSecrets(findings: GitleaksFinding[]): CategoryScore {
  if (findings.length === 0) {
    return {
      category: 'exposed_secrets',
      score: 100,
      applicable: true,
      message: 'No exposed secrets detected',
      findingCount: 0,
    };
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    const severity = classifyRule(finding.RuleID ?? 'unknown', finding.Entropy);
    counts[severity]++;
  }

  if (counts.critical > 0) {
    return {
      category: 'exposed_secrets',
      score: 0,
      applicable: true,
      message: `${counts.critical} critical secret(s) detected`,
      findingCount: findings.length,
    };
  }

  const penalty = counts.high * 25 + counts.medium * 10 + counts.low * 3;
  const score = clampScore(100 - penalty);

  return {
    category: 'exposed_secrets',
    score,
    applicable: true,
    message: `${findings.length} potential secret(s) detected`,
    findingCount: findings.length,
  };
}

async function parseReport(reportPath: string): Promise<GitleaksFinding[]> {
  const raw = await readFile(reportPath, 'utf8');
  if (!raw.trim()) return [];

  // gitleaks v8.30.0 emits a top-level JSON array; the { findings } branch is
  // defensive for older formats and malformed partial writes caught by catch below
  const parsed = JSON.parse(raw) as GitleaksFinding[] | { findings?: GitleaksFinding[] };
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed.findings)) return parsed.findings;
  return [];
}

export async function runGitleaks(ctx: ToolRunContext): Promise<CategoryScore[]> {
  const { repoDir, scanId, logger, signal } = ctx;
  const reportPath = path.join(REPORT_DIR, `gitleaks-${scanId}.json`);

  try {
    const result = await runTool({
      cmd: 'gitleaks',
      args: ['dir', repoDir, '--report-format', 'json', '--report-path', reportPath, '--no-banner'],
      label: 'gitleaks',
      logger,
      signal,
      expectedExitCodes: [1],
    });

    if (result.status === 'timeout') {
      return toolFailedScores(['exposed_secrets'], 'gitleaks timed out');
    }
    if (result.status === 'crash') {
      return toolFailedScores(['exposed_secrets'], 'gitleaks crashed');
    }

    const findings = await parseReport(reportPath);
    return [scoreSecrets(findings)];
  } catch (err) {
    const message = err instanceof Error ? err.message : 'gitleaks parse error';
    logger.error('tool', 'gitleaks parser failed', { error: message });
    return toolFailedScores(['exposed_secrets'], message);
  } finally {
    await rm(reportPath, { force: true });
  }
}
