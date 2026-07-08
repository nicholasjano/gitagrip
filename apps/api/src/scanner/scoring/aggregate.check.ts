// self-check for the scoring engine (issue #16) — run with:
//   pnpm --filter @gitagrip/api exec tsx src/scanner/scoring/aggregate.check.ts

import assert from 'node:assert/strict';
import { tierForCategory } from '@gitagrip/shared';
import { computeOverallScore } from './aggregate.js';
import { isTinyRepo, scoreRepositoryOverview } from './repo-overview.js';
import { combineWorkflowSecurity } from './scorecard-categories.js';
import type { CategoryScore, PartialToolScore } from '../types.js';
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

  // 7. isTinyRepo — Lizard crash on a small source set is tiny (the #2 fix)
  {
    const crashed: PartialToolScore = {
      score: 0,
      detail: '',
      failed: true,
      failureReason: 'crashed',
    };
    assert.equal(
      isTinyRepo(10, 2, crashed, true),
      true,
      'tiny: Lizard crash + 2 source files = tiny',
    );
    // large source set + Lizard crash -> NOT tiny (don't ban big repos on a crash)
    assert.equal(
      isTinyRepo(200, 50, crashed, true),
      false,
      'tiny: Lizard crash + 50 source files = not tiny',
    );
    // measured trivial NLOC -> tiny
    const measured: PartialToolScore = { score: 90, detail: 'ok', failed: false, nloc: 30 };
    assert.equal(isTinyRepo(20, 5, measured, true), true, 'tiny: NLOC 30 < 100 = tiny');
    // measured healthy NLOC -> not tiny
    const healthy: PartialToolScore = { score: 90, detail: 'ok', failed: false, nloc: 5000 };
    assert.equal(isTinyRepo(200, 50, healthy, true), false, 'tiny: NLOC 5000 = not tiny');
  }

  // 8. combineWorkflowSecurity — Opengrep tool-failure renormalizes to Scorecard (the #4 fix)
  //    without the guard: (80*0.7 + 0*0.3) = 56. with the guard: 80*0.7/0.7 = 80.
  {
    const scorecard: CategoryScore = {
      category: 'workflow_security',
      score: 80,
      applicable: true,
      message: 'Scorecard',
    };
    const opengrepFailed: CategoryScore = {
      category: 'workflow_security',
      score: 0,
      applicable: true,
      message: 'Tool failed: opengrep crashed',
      findingCount: 0,
    };
    const result = combineWorkflowSecurity(scorecard, opengrepFailed, true);
    assert.equal(result.score, 80, 'combiner: Opengrep crash renormalizes to Scorecard portion');
    assert.equal(result.applicable, true, 'combiner: still applicable');
  }

  console.log('aggregate.check: all assertions passed');
}

run();
