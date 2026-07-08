// category combinators for Scorecard-fed categories (issue #15).
// each blends the Scorecard portion with file/Opengrep/SECURITY.md portions
// at the issue's weights. when a portion is unavailable (tool failed/N/A),
// the surviving portions renormalize to 100% — same pattern as combineCodeQuality.

import { clampScore, isToolFailure, notApplicableScore, type CategoryScore } from '../types.js';

interface Portion {
  score: number;
  weight: number;
  available: boolean;
}

// renormalizing weighted average: usable portions scaled so their weights
// sum to 1. returns null if no portion is usable.
function weightedAverage(portions: Portion[]): number | null {
  const usable = portions.filter((p) => p.available);
  if (usable.length === 0) return null;
  const totalWeight = usable.reduce((acc, p) => acc + p.weight, 0);
  const weighted = usable.reduce((acc, p) => acc + p.score * p.weight, 0);
  return clampScore(weighted / totalWeight);
}

function scorecardAvailable(s: CategoryScore | null): boolean {
  return s !== null && s.applicable;
}

// non-Scorecard portion is usable only if applicable AND not a tool-failure 0.
// matches pickWorse in aggregate.ts: a crashed tool's placeholder 0 must not
// penalize the blend — it renormalizes away to the surviving portions.
function portionAvailable(s: CategoryScore): boolean {
  return s.applicable && !isToolFailure(s);
}

// cicd_devops = file-based check (40%) + Scorecard CI-Tests/Branch-Protection (60%)
// Gap C: Scorecard can un-N/A the category when no CI files were detected locally.
export function combineCICDDevops(
  scorecardScore: CategoryScore | null,
  fileScore: CategoryScore,
  applicable: boolean,
): CategoryScore {
  const sc = scorecardAvailable(scorecardScore);
  const file = portionAvailable(fileScore);
  // Scorecard present -> applicable regardless of file-based detection
  const isApplicable = sc || applicable;

  if (!isApplicable) {
    return notApplicableScore('cicd_devops', 'No CI or DevOps tooling detected');
  }

  const score = weightedAverage([
    { score: scorecardScore?.score ?? 0, weight: 0.6, available: sc },
    { score: fileScore.score, weight: 0.4, available: file },
  ]);

  if (score === null) {
    return {
      category: 'cicd_devops',
      score: 0,
      applicable: true,
      message: 'Tool failed: cicd_devops portions unavailable',
      findingCount: 0,
    };
  }

  const parts: string[] = [];
  if (sc) parts.push('Scorecard');
  if (file) parts.push(fileScore.message);
  return {
    category: 'cicd_devops',
    score,
    applicable: true,
    message: parts.length > 0 ? parts.join('; ') : 'cicd_devops',
  };
}

// repo_security_posture = Scorecard (70%) + SECURITY.md (30%)
// Opengrep dropped: classifyFinding never routes findings here, so the Opengrep
// portion was a constant 100 that inflated the category. Scorecard's
// Security-Policy/SAST/Binary-Artifacts/Signed-Releases checks carry the real
// posture signal. always-applicable per applicability.ts; SECURITY.md is always usable.
export function combineRepoSecurityPosture(
  scorecardScore: CategoryScore | null,
  hasSecurityPolicy: boolean,
): CategoryScore {
  const sc = scorecardAvailable(scorecardScore);

  const score = weightedAverage([
    { score: scorecardScore?.score ?? 0, weight: 0.7, available: sc },
    { score: hasSecurityPolicy ? 100 : 0, weight: 0.3, available: true },
  ]);

  // SECURITY.md alone guarantees a non-null score, but guard anyway
  if (score === null) {
    return {
      category: 'repo_security_posture',
      score: 0,
      applicable: true,
      message: 'Tool failed: repo_security_posture portions unavailable',
      findingCount: 0,
    };
  }

  const parts: string[] = [];
  if (sc) parts.push('Scorecard');
  parts.push(hasSecurityPolicy ? 'SECURITY.md present' : 'no SECURITY.md');
  return {
    category: 'repo_security_posture',
    score,
    applicable: true,
    message: parts.join('; '),
  };
}

// workflow_security = Scorecard (70%) + Opengrep Actions rules (30%)
// conditional on hasWorkflowFiles; if not applicable, N/A.
export function combineWorkflowSecurity(
  scorecardScore: CategoryScore | null,
  opengrepScore: CategoryScore,
  applicable: boolean,
): CategoryScore {
  if (!applicable) {
    return notApplicableScore('workflow_security', 'No GitHub Actions workflows detected');
  }

  const sc = scorecardAvailable(scorecardScore);
  const og = portionAvailable(opengrepScore);

  const score = weightedAverage([
    { score: scorecardScore?.score ?? 0, weight: 0.7, available: sc },
    { score: opengrepScore.score, weight: 0.3, available: og },
  ]);

  if (score === null) {
    return {
      category: 'workflow_security',
      score: 0,
      applicable: true,
      message: 'Tool failed: workflow_security portions unavailable',
      findingCount: 0,
    };
  }

  const parts: string[] = [];
  if (sc) parts.push('Scorecard');
  if (og) parts.push('Opengrep Actions');
  return {
    category: 'workflow_security',
    score,
    applicable: true,
    message: parts.length > 0 ? parts.join('; ') : 'workflow_security',
  };
}
