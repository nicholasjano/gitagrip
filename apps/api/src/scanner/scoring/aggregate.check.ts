// self-check for the scoring engine (issue #16) — run with:
//   pnpm --filter @gitagrip/api exec tsx src/scanner/scoring/aggregate.check.ts

import assert from 'node:assert/strict';
import { tierForCategory } from '@gitagrip/shared';
import { computeOverallScore } from './aggregate.js';
import { scoreRepositoryOverview } from './repo-overview.js';
import type { CategoryScore } from '../types.js';
import type { ScanCategoryName } from '../applicability.js';

function score(
  category: ScanCategoryName,
  sc: number,
  applicable: boolean,
  message: string,
): CategoryScore {
  return { category, score: sc, applicable, message };
}

function run(): void {
  // 1. dedup: real 40 + tool-failure 0 -> one row scoring 40
  {
    const result = computeOverallScore([
      score('security_vulnerabilities', 40, true, 'No findings detected'),
      score('security_vulnerabilities', 0, true, 'Tool failed: opengrep crashed'),
    ]);
    assert.equal(result.categories.length, 1, 'dedup: should collapse to one row');
    assert.equal(result.categories[0]!.score, 40, 'dedup: real score beats tool-failure 0');
  }

  // 2. N/A excluded from weighted average (N/A critical does not drag to 0)
  {
    const result = computeOverallScore([
      score('exposed_secrets', 100, true, 'clean'),
      score('container_security', 0, false, 'no docker'),
    ]);
    assert.equal(result.overallScore, 100, 'N/A excluded: applicable-only average');
    assert.equal(result.naCount, 1, 'naCount correct');
    assert.equal(result.applicableCount, 1, 'applicableCount correct');
  }

  // 3. all-applicable weighting matches hand-computed value
  //    exposed_secrets (critical w3) 60 + code_quality (standard w1) 80
  //    = (60*3 + 80*1) / (3+1) = 260/4 = 65
  {
    const result = computeOverallScore([
      score('exposed_secrets', 60, true, 'clean'),
      score('code_quality', 80, true, 'good'),
    ]);
    assert.equal(result.overallScore, 65, 'weighted average matches hand calc');
  }

  // 4. N/A messages normalized + counts
  {
    const result = computeOverallScore([
      score('dockerfile_best_practices', 50, false, 'something else'),
      score('exposed_secrets', 100, true, 'clean'),
    ]);
    const na = result.categories.find((c) => c.category === 'dockerfile_best_practices')!;
    assert.equal(na.score, 0, 'N/A score forced to 0');
    assert.equal(na.message, 'N/A - no Dockerfile found in repository', 'N/A message normalized');
    assert.equal(result.naCount, 1, 'naCount correct');
    assert.equal(result.applicableCount, 1, 'applicableCount correct');
  }

  // 5. tierForCategory — one per tier
  assert.equal(tierForCategory('exposed_secrets'), 'critical', 'tier: critical');
  assert.equal(tierForCategory('dockerfile_best_practices'), 'high', 'tier: high');
  assert.equal(tierForCategory('code_quality'), 'standard', 'tier: standard');

  // 6. scoreRepositoryOverview — maxed input hits 100, clamped
  {
    const maxed = scoreRepositoryOverview({
      stars: 200,
      sizeKb: 100,
      language: 'TypeScript',
      isFork: false,
      description: 'A great repo',
    });
    assert.equal(maxed.score, 100, 'repo-overview: maxed = 100');
    assert.equal(maxed.applicable, true, 'repo-overview: always applicable');
  }
  {
    const empty = scoreRepositoryOverview({
      stars: 0,
      sizeKb: 1_000_000,
      language: null,
      isFork: true,
      description: null,
    });
    assert.equal(empty.score, 0, 'repo-overview: empty = 0 (clamped)');
  }

  console.log('aggregate.check: all assertions passed');
}

run();
