// maintenance_community scoring — GitHub API metadata (last commit age + stars)
// blended with the OSSF Scorecard portion (Maintained, Code-Review, Contributors).
// per issue #15: Scorecard 60% + API metadata 40%. When Scorecard is unavailable
// (skipped/failed/all-inconclusive), the API portion renormalizes to 100%.

import { clampScore, type CategoryScore } from '../types.js';

// API portion (the 40% weight): last commit age is the primary signal,
// stars > 100 adds a +10 bonus capped at 100. open-issues ratio was dropped
// (ill-defined denominator + paginated calls too rate-limit heavy).
export function scoreMaintenanceApi(pushedAt: Date | null, stars: number): number {
  let base: number;
  if (!pushedAt) {
    base = 20; // unknown -> treat as stale
  } else {
    const ageDays = (Date.now() - pushedAt.getTime()) / (1000 * 60 * 60 * 24);
    if (ageDays < 30) base = 100;
    else if (ageDays < 90) base = 80;
    else if (ageDays < 365) base = 50;
    else base = 20;
  }
  if (stars > 100) base = Math.min(100, base + 10);
  return base;
}

// scorecardScore: null = Scorecard crashed/skipped entirely; applicable=false =
// all mapped checks inconclusive. Either way the Scorecard portion is absent
// and the API portion renormalizes to 100%.
export function combineMaintenance(
  scorecardScore: CategoryScore | null,
  pushedAt: Date | null,
  stars: number,
): CategoryScore {
  const apiPortion = scoreMaintenanceApi(pushedAt, stars);
  const hasScorecard = scorecardScore !== null && scorecardScore.applicable;

  if (!hasScorecard) {
    const reason =
      scorecardScore === null
        ? 'OSSF Scorecard unavailable, API metadata only'
        : scorecardScore.message;
    return {
      category: 'maintenance_community',
      score: clampScore(apiPortion),
      applicable: true,
      message: reason,
    };
  }

  return {
    category: 'maintenance_community',
    score: clampScore(scorecardScore.score * 0.6 + apiPortion * 0.4),
    applicable: true,
    message: 'OSSF Scorecard + GitHub API metadata',
  };
}
