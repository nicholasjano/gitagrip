// aggregation engine — dedup per-category, weight by tier, produce overall score.
// dedup is REQUIRED: security_vulnerabilities appears twice (trivy + opengrep) and
// scan_categories has a unique(scan_id, category) index — without dedup the insert throws.

import { tierForCategory, type ScanCategoryName as SharedScanCategoryName } from '@gitagrip/shared';
import { type CategoryScore, clampScore, isToolFailure } from '../types.js';
import type { ScanCategoryName } from '../applicability.js';
import { weightForCategory } from './tiers.js';

export interface ScoringResult {
  overallScore: number;
  categories: CategoryScore[];
  applicableCount: number;
  naCount: number;
  leaderboardEligible: boolean;
  tierBreakdown: { critical: number; high: number; standard: number };
}

// canonical N/A messages — only the 7 conditional categories can be N/A
const NA_MESSAGES: Partial<Record<ScanCategoryName, string>> = {
  dockerfile_best_practices: 'N/A - no Dockerfile found in repository',
  container_security: 'N/A - no Dockerfile or docker-compose found',
  iac_security: 'N/A - no Terraform, CloudFormation, or Kubernetes files found',
  dependency_health: 'N/A - no package lock files found',
  code_quality: 'N/A - no supported source files found',
  cicd_devops: 'N/A - no CI/CD configuration found',
  workflow_security: 'N/A - no GitHub Actions workflow files found',
};

// on collision keep the worst: a real score beats a tool-failure 0;
// among two real scores the lower wins; among two failures either 0 is fine.
function pickWorse(a: CategoryScore, b: CategoryScore): CategoryScore {
  const aFail = isToolFailure(a);
  const bFail = isToolFailure(b);
  if (aFail && !bFail) return b;
  if (!aFail && bFail) return a;
  return b.score < a.score ? b : a;
}

export function computeOverallScore(categories: CategoryScore[]): ScoringResult {
  // 1. dedup into ≤13 unique category rows
  const deduped = new Map<ScanCategoryName, CategoryScore>();
  for (const score of categories) {
    const existing = deduped.get(score.category);
    deduped.set(score.category, existing ? pickWorse(existing, score) : score);
  }

  // 2. normalize N/A messages + force score 0
  const normalized: CategoryScore[] = [];
  for (const score of deduped.values()) {
    if (!score.applicable) {
      const canonical = NA_MESSAGES[score.category];
      normalized.push({
        ...score,
        score: 0,
        message: canonical ?? score.message,
      });
    } else {
      normalized.push(score);
    }
  }

  const applicable = normalized.filter((s) => s.applicable);
  const naCount = normalized.length - applicable.length;

  // 3. weighted average over applicable categories only
  let weightSum = 0;
  let weightedTotal = 0;
  for (const score of applicable) {
    const w = weightForCategory(score.category);
    weightSum += w;
    weightedTotal += score.score * w;
  }
  const overallScore = weightSum > 0 ? clampScore(weightedTotal / weightSum) : 0;

  // 4. tier breakdown — rounded mean of applicable scores per tier
  const tierBreakdown = { critical: 0, high: 0, standard: 0 };
  for (const tier of ['critical', 'high', 'standard'] as const) {
    const inTier = applicable.filter(
      (s) => tierForCategory(s.category as SharedScanCategoryName) === tier,
    );
    if (inTier.length > 0) {
      tierBreakdown[tier] = Math.round(inTier.reduce((acc, s) => acc + s.score, 0) / inTier.length);
    }
  }

  return {
    overallScore,
    categories: normalized,
    applicableCount: applicable.length,
    naCount,
    leaderboardEligible: applicable.length >= 6,
    tierBreakdown,
  };
}
