// OSSF Scorecard runner + parser — Phase A (API-bound) tool.
// Runs the scorecard binary against a GitHub repo, parses checks[] into
// per-category portions (0-100). Category enrichment/weighting happens in
// scoring/scorecard-categories.ts and scoring/maintenance.ts.

import { runTool } from '../run-tool.js';
import { notApplicableScore, type CategoryScore, type ToolRunContext } from '../types.js';
import type { ScanSelect } from '../../db/schema.js';
import { hasScorecardTokens, getNextToken, logRateLimit } from './scorecard-tokens.js';
// Scorecard check name -> category. Names match scorecard's JSON `checks[].name`
// exactly (case-sensitive). See https://github.com/ossf/scorecard/blob/main/docs/checks.md
const CHECK_TO_CATEGORY: Record<string, CategoryScore['category']> = {
  Maintained: 'maintenance_community',
  'Code-Review': 'maintenance_community',
  Contributors: 'maintenance_community',
  'CI-Tests': 'cicd_devops',
  'Branch-Protection': 'cicd_devops',
  'Dependency-Update-Tool': 'cicd_devops',
  'Security-Policy': 'repo_security_posture',
  SAST: 'repo_security_posture',
  'Binary-Artifacts': 'repo_security_posture',
  'Signed-Releases': 'repo_security_posture',
  'Token-Permissions': 'workflow_security',
  'Pinned-Dependencies': 'workflow_security',
  'Dangerous-Workflow': 'workflow_security',
};

const SCORECARD_CATEGORIES: CategoryScore['category'][] = [
  'maintenance_community',
  'cicd_devops',
  'repo_security_posture',
  'workflow_security',
];

const SCORECARD_TIMEOUT_MS = 120_000;

interface ScorecardCheck {
  name?: string;
  score?: number; // 0-10, or -1 for inconclusive
  reason?: string;
  details?: string[];
}

interface ScorecardReport {
  checks?: ScorecardCheck[];
}

function naAll(reason: string): CategoryScore[] {
  return SCORECARD_CATEGORIES.map((c) => notApplicableScore(c, reason));
}

// mean of non-(-1) check scores * 10. Returns null if all checks are -1
// (inconclusive) so the category degrades to its non-Scorecard portions.
function categoryPortion(checks: ScorecardCheck[]): number | null {
  const usable = checks.filter((c) => typeof c.score === 'number' && c.score >= 0);
  if (usable.length === 0) return null;
  const sum = usable.reduce((acc, c) => acc + (c.score as number), 0);
  return Math.round((sum / usable.length) * 10);
}

export function parseScorecardChecks(raw: string): Record<string, number | null> {
  const report = JSON.parse(raw) as ScorecardReport;
  const byCategory: Record<string, ScorecardCheck[]> = {
    maintenance_community: [],
    cicd_devops: [],
    repo_security_posture: [],
    workflow_security: [],
  };

  for (const check of report.checks ?? []) {
    const category = CHECK_TO_CATEGORY[check.name ?? ''];
    if (!category) continue;
    byCategory[category]!.push(check);
  }

  const portions: Record<string, number | null> = {};
  for (const category of SCORECARD_CATEGORIES) {
    portions[category] = categoryPortion(byCategory[category] ?? []);
  }
  return portions;
}

function isRateLimited(stderr: string): boolean {
  return /rate limit/i.test(stderr);
}

export async function runScorecard(
  ctx: ToolRunContext & { scan: Pick<ScanSelect, 'repoOwner' | 'repoName' | 'isPrivate'> },
): Promise<CategoryScore[]> {
  const { logger, signal, scan } = ctx;
  const { repoOwner, repoName, isPrivate } = scan;

  // pre-flight: no tokens -> skip entirely
  if (!hasScorecardTokens()) {
    return naAll('OSSF Scorecard skipped: no GitHub token configured');
  }
  // pre-flight: private repos unreachable with public_repo-scope tokens
  if (isPrivate) {
    return naAll('OSSF Scorecard skipped: private repository');
  }

  const repoArg = `github.com/${repoOwner}/${repoName}`;

  // one run + one retry on rate limit with a different token. crash/timeout
  // -> degrade (return N/A). rate limit on both tokens -> throw regular Error
  // so BullMQ backoff retries the whole scan.
  for (let attempt = 0; attempt < 2; attempt++) {
    const token = await getNextToken();
    await logRateLimit(token, logger);

    let result;
    try {
      result = await runTool({
        cmd: 'scorecard',
        args: ['--repo', repoArg, '--format', 'json'],
        env: { ...process.env, GITHUB_AUTH_TOKEN: token },
        signal,
        timeoutMs: SCORECARD_TIMEOUT_MS,
        label: 'scorecard',
        logger,
        // scorecard writes JSON to stdout; keep a generous buffer
        maxBuffer: 16 * 1024 * 1024,
      });
    } catch (err) {
      // runTool itself shouldn't throw (it returns status), but be defensive
      logger.warn('scorecard', `run threw: ${(err as Error).message}`);
      return naAll(`Scorecard run error: ${(err as Error).message}`);
    }

    // crash/timeout only: distinguish a rate-limit from a genuine failure.
    // A real GitHub rate-limit makes scorecard exit non-zero -> runTool
    // classifies it 'crash', preserving the rate-limit text in stderr
    // (run-tool.ts keeps e.stderr on the error path). Gate on this no-usable-
    // output path so a rate-limit warning in the stderr of an otherwise-
    // successful run (some checks -1, valid JSON on stdout) still flows to the
    // parser and degrades per-check, instead of failing the whole scan.
    if (result.status === 'crash' || result.status === 'timeout') {
      // rate limited -> try a different token once, else throw for BullMQ retry
      if (isRateLimited(result.stderr)) {
        if (attempt === 0) {
          logger.warn('scorecard', 'rate limited, retrying with next token');
          continue;
        }
        throw new Error('Scorecard rate limited across all token retries');
      }
      // genuine crash/timeout -> degrade, don't fail the scan
      logger.warn('scorecard', `scorecard ${result.status}, degrading`);
      return naAll(`Scorecard ${result.status}`);
    }

    // parse JSON -> category portions
    try {
      const portions = parseScorecardChecks(result.stdout);
      return SCORECARD_CATEGORIES.map((category) => {
        const portion = portions[category] ?? null;
        if (portion === null) {
          return notApplicableScore(category, 'OSSF Scorecard: all mapped checks inconclusive');
        }
        return {
          category,
          score: portion,
          applicable: true,
          message: 'OSSF Scorecard',
        };
      });
    } catch (err) {
      logger.warn('scorecard', `parse error: ${(err as Error).message}`);
      return naAll(`Scorecard JSON parse error: ${(err as Error).message}`);
    }
  }

  // ponytail: unreachable in practice (loop covers both attempts), but TS
  // needs a return on the exhaustive path
  return naAll('Scorecard exhausted retries');
}
