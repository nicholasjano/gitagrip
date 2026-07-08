// temp test: scoring engine (issue #16)
// run: pnpm --filter @gitagrip/api exec tsx tmp/scoring-engine.test.ts

import assert from 'node:assert/strict';
import { computeOverallScore } from '../src/scanner/scoring/aggregate.js';
import { scoreRepositoryOverview } from '../src/scanner/scoring/repo-overview.js';
import { weightForCategory } from '../src/scanner/scoring/tiers.js';
import { tierForCategory, type ScanCategoryName } from '@gitagrip/shared';
import type { CategoryScore } from '../src/scanner/types.js';

function s(
  category: ScanCategoryName,
  score: number,
  applicable: boolean,
  message: string,
): CategoryScore {
  return { category, score, applicable, message };
}

const ALL_13: ScanCategoryName[] = [
  'repository_overview',
  'maintenance_community',
  'documentation_standards',
  'security_vulnerabilities',
  'exposed_secrets',
  'dependency_health',
  'code_quality',
  'cicd_devops',
  'repo_security_posture',
  'workflow_security',
  'iac_security',
  'dockerfile_best_practices',
  'container_security',
];

function passed(name: string): void {
  console.log(`  ✓ ${name}`);
}

// ─── Tier weights ──────────────────────────────────────────────────

function testTierWeights(): void {
  console.log('\n[1] Tier weights');

  assert.equal(tierForCategory('exposed_secrets'), 'critical');
  assert.equal(tierForCategory('security_vulnerabilities'), 'critical');
  assert.equal(tierForCategory('container_security'), 'critical');
  assert.equal(tierForCategory('workflow_security'), 'critical');
  assert.equal(tierForCategory('repo_security_posture'), 'critical');
  passed('5 critical-tier categories');

  assert.equal(tierForCategory('dockerfile_best_practices'), 'high');
  assert.equal(tierForCategory('iac_security'), 'high');
  assert.equal(tierForCategory('dependency_health'), 'high');
  assert.equal(tierForCategory('cicd_devops'), 'high');
  passed('4 high-tier categories');

  assert.equal(tierForCategory('code_quality'), 'standard');
  assert.equal(tierForCategory('maintenance_community'), 'standard');
  assert.equal(tierForCategory('documentation_standards'), 'standard');
  assert.equal(tierForCategory('repository_overview'), 'standard');
  passed('4 standard-tier categories');

  assert.equal(weightForCategory('exposed_secrets'), 3, 'critical weight = 3');
  assert.equal(weightForCategory('dockerfile_best_practices'), 2, 'high weight = 2');
  assert.equal(weightForCategory('code_quality'), 1, 'standard weight = 1');
  passed('weightForCategory returns 3/2/1 for critical/high/standard');
}

// ─── Dedup ─────────────────────────────────────────────────────────

function testDedup(): void {
  console.log('\n[2] Dedup (security_vulnerabilities collision)');

  // two real scores → worst wins
  {
    const result = computeOverallScore([
      s('security_vulnerabilities', 40, true, 'trivy: 2 high vulns'),
      s('security_vulnerabilities', 30, true, 'opengrep: 5 warnings'),
    ]);
    assert.equal(result.categories.length, 1, 'collapses to 1 row');
    assert.equal(result.categories[0]!.score, 30, 'worst (lower) real score wins');
    passed('two real scores → worst (30) wins');
  }

  // real + tool-failure → real wins (failure 0 does not beat real score)
  {
    const result = computeOverallScore([
      s('security_vulnerabilities', 85, true, 'No findings detected'),
      s('security_vulnerabilities', 0, true, 'Tool failed: opengrep crashed'),
    ]);
    assert.equal(result.categories.length, 1);
    assert.equal(result.categories[0]!.score, 85, 'real score beats tool-failure 0');
    passed('real 85 + failure 0 → real 85 wins');
  }

  // both tool failures → keep one 0
  {
    const result = computeOverallScore([
      s('security_vulnerabilities', 0, true, 'Tool failed: trivy timed out'),
      s('security_vulnerabilities', 0, true, 'Tool failed: opengrep crashed'),
    ]);
    assert.equal(result.categories.length, 1);
    assert.equal(result.categories[0]!.score, 0);
    assert.ok(
      result.categories[0]!.message.startsWith('Tool failed:'),
      'failure message preserved',
    );
    passed('two failures → one 0 row');
  }

  // dedup is generic — works for any category
  {
    const result = computeOverallScore([
      s('exposed_secrets', 100, true, 'clean'),
      s('exposed_secrets', 50, true, '1 medium secret'),
    ]);
    assert.equal(result.categories.length, 1);
    assert.equal(result.categories[0]!.score, 50, 'worst wins for any category');
    passed('generic dedup works on exposed_secrets');
  }
}

// ─── N/A handling ──────────────────────────────────────────────────

function testNaHandling(): void {
  console.log('\n[3] N/A handling');

  // N/A excluded from weighted average
  {
    const result = computeOverallScore([
      s('exposed_secrets', 100, true, 'clean'),
      s('container_security', 0, false, 'no docker'),
    ]);
    assert.equal(result.overallScore, 100, 'N/A does not drag average');
    assert.equal(result.naCount, 1);
    assert.equal(result.applicableCount, 1);
    passed('N/A excluded from weighted average');
  }

  // all 7 N/A messages normalized
  {
    const naCategories: Array<[ScanCategoryName, string]> = [
      ['dockerfile_best_practices', 'N/A - no Dockerfile found in repository'],
      ['container_security', 'N/A - no Dockerfile or docker-compose found'],
      ['iac_security', 'N/A - no Terraform, CloudFormation, or Kubernetes files found'],
      ['dependency_health', 'N/A - no package lock files found'],
      ['code_quality', 'N/A - no supported source files found'],
      ['cicd_devops', 'N/A - no CI/CD configuration found'],
      ['workflow_security', 'N/A - no GitHub Actions workflow files found'],
    ];
    for (const [cat, expectedMsg] of naCategories) {
      const result = computeOverallScore([
        s(cat, 50, false, 'original tool message'),
        s('exposed_secrets', 100, true, 'clean'),
      ]);
      const na = result.categories.find((c) => c.category === cat)!;
      assert.equal(na.message, expectedMsg, `${cat} message normalized`);
      assert.equal(na.score, 0, `${cat} score forced to 0`);
      assert.equal(na.applicable, false, `${cat} applicable stays false`);
    }
    passed('all 7 N/A messages normalized to canonical text');
  }

  // N/A score forced to 0 even if tool emitted non-zero
  {
    const result = computeOverallScore([
      s('dockerfile_best_practices', 75, false, 'should be zeroed'),
      s('exposed_secrets', 100, true, 'clean'),
    ]);
    const na = result.categories.find((c) => c.category === 'dockerfile_best_practices')!;
    assert.equal(na.score, 0, 'non-zero N/A score forced to 0');
    passed('N/A score forced to 0');
  }
}

// ─── Weighted average ──────────────────────────────────────────────

function testWeightedAverage(): void {
  console.log('\n[4] Weighted average');

  // exposed_secrets (critical, w3) 60 + code_quality (standard, w1) 80
  // = (60*3 + 80*1) / (3+1) = 260/4 = 65
  {
    const result = computeOverallScore([
      s('exposed_secrets', 60, true, 'clean'),
      s('code_quality', 80, true, 'good'),
    ]);
    assert.equal(result.overallScore, 65, 'hand-computed weighted average');
    passed('critical 3x + standard 1x = 65');
  }

  // all critical, all 50 → 50
  {
    const result = computeOverallScore([
      s('exposed_secrets', 50, true, 'ok'),
      s('security_vulnerabilities', 50, true, 'ok'),
    ]);
    assert.equal(result.overallScore, 50, 'same-tier average');
    passed('two critical 50s → 50');
  }

  // empty input → 0
  {
    const result = computeOverallScore([]);
    assert.equal(result.overallScore, 0, 'empty → 0');
    assert.equal(result.categories.length, 0);
    assert.equal(result.applicableCount, 0);
    assert.equal(result.naCount, 0);
    passed('empty input → 0');
  }

  // all N/A → 0, 0 applicable
  {
    const result = computeOverallScore([
      s('dockerfile_best_practices', 0, false, 'no docker'),
      s('container_security', 0, false, 'no docker'),
    ]);
    assert.equal(result.overallScore, 0, 'all N/A → 0');
    assert.equal(result.applicableCount, 0);
    assert.equal(result.naCount, 2);
    passed('all N/A → score 0, 0 applicable');
  }

  // full 13-category input, all 80 → 80 (weight doesn't matter when uniform)
  {
    const all80 = ALL_13.map((c) => s(c, 80, true, 'uniform'));
    const result = computeOverallScore(all80);
    assert.equal(result.overallScore, 80, 'uniform 80 → 80');
    assert.equal(result.categories.length, 13);
    assert.equal(result.applicableCount, 13);
    passed('13 categories all 80 → 80');
  }
}

// ─── Tier breakdown ────────────────────────────────────────────────

function testTierBreakdown(): void {
  console.log('\n[5] Tier breakdown');

  {
    const result = computeOverallScore([
      s('exposed_secrets', 90, true, 'clean'), // critical
      s('security_vulnerabilities', 60, true, '2 vulns'), // critical
      s('dockerfile_best_practices', 80, true, 'ok'), // high
      s('code_quality', 70, true, 'good'), // standard
    ]);
    assert.equal(result.tierBreakdown.critical, 75, '(90+60)/2 = 75');
    assert.equal(result.tierBreakdown.high, 80, 'single high = 80');
    assert.equal(result.tierBreakdown.standard, 70, 'single standard = 70');
    passed('tier breakdown = rounded mean per tier');
  }

  // empty tier → 0
  {
    const result = computeOverallScore([s('exposed_secrets', 100, true, 'clean')]);
    assert.equal(result.tierBreakdown.critical, 100);
    assert.equal(result.tierBreakdown.high, 0, 'no high → 0');
    assert.equal(result.tierBreakdown.standard, 0, 'no standard → 0');
    passed('empty tier → 0');
  }
}

// ─── Leaderboard eligibility ───────────────────────────────────────

function testLeaderboardEligibility(): void {
  console.log('\n[6] Leaderboard eligibility (>= 6 applicable)');

  // 6 applicable → eligible
  {
    const six: CategoryScore[] = [
      s('repository_overview', 50, true, 'ok'),
      s('maintenance_community', 50, true, 'ok'),
      s('documentation_standards', 50, true, 'ok'),
      s('security_vulnerabilities', 50, true, 'ok'),
      s('exposed_secrets', 50, true, 'ok'),
      s('repo_security_posture', 50, true, 'ok'),
    ];
    const result = computeOverallScore(six);
    assert.equal(result.leaderboardEligible, true, '6 applicable → eligible');
    passed('6 applicable → eligible');
  }

  // 5 applicable → not eligible
  {
    const five: CategoryScore[] = [
      s('repository_overview', 50, true, 'ok'),
      s('maintenance_community', 50, true, 'ok'),
      s('documentation_standards', 50, true, 'ok'),
      s('security_vulnerabilities', 50, true, 'ok'),
      s('exposed_secrets', 50, true, 'ok'),
    ];
    const result = computeOverallScore(five);
    assert.equal(result.leaderboardEligible, false, '5 applicable → not eligible');
    passed('5 applicable → not eligible');
  }

  // 6 always-applicable + 7 N/A → eligible (the realistic case)
  {
    const sixReal: CategoryScore[] = [
      s('repository_overview', 50, true, 'ok'),
      s('maintenance_community', 50, true, 'ok'),
      s('documentation_standards', 50, true, 'ok'),
      s('security_vulnerabilities', 50, true, 'ok'),
      s('exposed_secrets', 50, true, 'ok'),
      s('repo_security_posture', 50, true, 'ok'),
      s('dockerfile_best_practices', 0, false, 'no docker'),
      s('container_security', 0, false, 'no docker'),
      s('iac_security', 0, false, 'no iac'),
      s('dependency_health', 0, false, 'no lockfiles'),
      s('code_quality', 0, false, 'no source'),
      s('cicd_devops', 0, false, 'no ci'),
      s('workflow_security', 0, false, 'no workflows'),
    ];
    const result = computeOverallScore(sixReal);
    assert.equal(result.leaderboardEligible, true, '6 applicable + 7 N/A → eligible');
    assert.equal(result.applicableCount, 6);
    assert.equal(result.naCount, 7);
    passed('6 applicable + 7 N/A → eligible (realistic minimal repo)');
  }
}

// ─── Repository overview scoring ───────────────────────────────────

function testRepoOverview(): void {
  console.log('\n[7] Repository overview scoring');

  // maxed input → 100
  {
    const maxed = scoreRepositoryOverview({
      stars: 200,
      sizeKb: 100,
      language: 'TypeScript',
      isFork: false,
      description: 'A great repo',
    });
    assert.equal(maxed.score, 100, '20+20+20+30+10 = 100');
    assert.equal(maxed.applicable, true, 'always applicable');
    assert.equal(maxed.category, 'repository_overview');
    passed('maxed input → 100');
  }

  // empty repo → 0
  {
    const empty = scoreRepositoryOverview({
      stars: 0,
      sizeKb: 1_000_000,
      language: null,
      isFork: true,
      description: null,
    });
    assert.equal(empty.score, 0, '0+0+0+0+0 = 0');
    passed('empty repo → 0');
  }

  // partial — language + not fork + stars > 0 = 20+20+10 = 50
  {
    const partial = scoreRepositoryOverview({
      stars: 5,
      sizeKb: 1_000_000,
      language: 'Python',
      isFork: false,
      description: null,
    });
    assert.equal(partial.score, 50, '20 (lang) + 20 (!fork) + 10 (stars>0) = 50');
    passed('partial input → 50');
  }

  // stars tiers: >0 → 10, >10 → 20, >100 → 30
  {
    const s1 = scoreRepositoryOverview({
      stars: 1,
      sizeKb: 999_000,
      language: null,
      isFork: true,
      description: null,
    });
    assert.equal(s1.score, 10, 'stars > 0 → 10');
    const s11 = scoreRepositoryOverview({
      stars: 11,
      sizeKb: 999_000,
      language: null,
      isFork: true,
      description: null,
    });
    assert.equal(s11.score, 20, 'stars > 10 → 20');
    const s101 = scoreRepositoryOverview({
      stars: 101,
      sizeKb: 999_000,
      language: null,
      isFork: true,
      description: null,
    });
    assert.equal(s101.score, 30, 'stars > 100 → 30');
    passed('stars tiered: >0→10, >10→20, >100→30');
  }

  // size boundary: exactly 512_000 KB → NOT < 512_000, no points
  {
    const boundary = scoreRepositoryOverview({
      stars: 0,
      sizeKb: 512_000,
      language: null,
      isFork: true,
      description: null,
    });
    assert.equal(boundary.score, 0, 'sizeKb === 512_000 → no points (strict <)');
    passed('size boundary: 512_000 KB → no size points');
  }

  // description whitespace-only → no points
  {
    const ws = scoreRepositoryOverview({
      stars: 0,
      sizeKb: 999_000,
      language: null,
      isFork: true,
      description: '   ',
    });
    assert.equal(ws.score, 0, 'whitespace-only description → no points');
    passed('whitespace description → 0');
  }

  // score clamps at 100 (over-max impossible with current formula, but test anyway)
  {
    const clamped = scoreRepositoryOverview({
      stars: 9999,
      sizeKb: 1,
      language: 'Go',
      isFork: false,
      description: 'desc',
    });
    assert.equal(clamped.score, 100, 'clamps at 100');
    passed('over-max → clamped to 100');
  }
}

// ─── Run all ───────────────────────────────────────────────────────

function main(): void {
  console.log('=== Scoring Engine Tests (Issue #16) ===');
  testTierWeights();
  testDedup();
  testNaHandling();
  testWeightedAverage();
  testTierBreakdown();
  testLeaderboardEligibility();
  testRepoOverview();
  console.log('\n=== ALL SCORING ENGINE TESTS PASSED ===\n');
}

main();
