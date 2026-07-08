// repository_overview scoring — pure function from scan-row metadata.
// always applicable; max 100. private repos add no points
// (ponytail: excluded from leaderboard by the DB partial index, no double-gate here).

import { clampScore, type CategoryScore } from '../types.js';

export interface RepoOverviewInput {
  stars: number;
  sizeKb: number;
  language: string | null;
  isFork: boolean;
  description: string | null;
}

export function scoreRepositoryOverview(input: RepoOverviewInput): CategoryScore {
  const { stars, sizeKb, language, isFork, description } = input;
  const signals: string[] = [];
  let score = 0;

  if (language !== null) {
    score += 20;
    signals.push(`language: ${language}`);
  }
  if (sizeKb < 512_000) {
    score += 20;
    signals.push('size < 500MB');
  }
  if (!isFork) {
    score += 20;
    signals.push('not a fork');
  }
  if (stars > 100) {
    score += 30;
    signals.push(`${stars} stars`);
  } else if (stars > 10) {
    score += 20;
    signals.push(`${stars} stars`);
  } else if (stars > 0) {
    score += 10;
    signals.push(`${stars} stars`);
  }
  if (description !== null && description.trim().length > 0) {
    score += 10;
    signals.push('has description');
  }

  return {
    category: 'repository_overview',
    score: clampScore(score),
    applicable: true,
    message: signals.length > 0 ? signals.join('; ') : 'minimal repository metadata',
  };
}
