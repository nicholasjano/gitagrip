// temp test: combiner functions (issue #15 blending + #14 code quality)
// run: pnpm --filter @gitagrip/api exec tsx tmp/combiners.test.ts

import assert from 'node:assert/strict';
import { combineCodeQuality } from '../src/scanner/scoring/code-quality.js';
import { combineMaintenance } from '../src/scanner/scoring/maintenance.js';
import {
  combineCICDDevops,
  combineRepoSecurityPosture,
  combineWorkflowSecurity,
} from '../src/scanner/scoring/scorecard-categories.js';
import type { CategoryScore, PartialToolScore } from '../src/scanner/types.js';

function passed(name: string): void {
  console.log(`  ✓ ${name}`);
}

function okPartial(score: number, detail: string): PartialToolScore {
  return { score, detail, failed: false };
}

function failPartial(reason: string): PartialToolScore {
  return { score: 0, detail: '', failed: true, failureReason: reason };
}

function cs(category: string, score: number, applicable: boolean, message: string): CategoryScore {
  return { category: category as CategoryScore['category'], score, applicable, message };
}

// ─── combineCodeQuality ────────────────────────────────────────────

function testCombineCodeQuality(): void {
  console.log('\n[1] combineCodeQuality');

  // not applicable → N/A
  {
    const result = combineCodeQuality(failPartial('skipped'), failPartial('skipped'), false);
    assert.equal(result.applicable, false);
    assert.equal(result.score, 0);
    passed('not applicable → N/A');
  }

  // both tools succeed → 0.6/0.4 blend
  // lizard 80 * 0.6 + jscpd 60 * 0.4 = 48 + 24 = 72
  {
    const result = combineCodeQuality(okPartial(80, 'lizard ok'), okPartial(60, 'jscpd ok'), true);
    assert.equal(result.applicable, true);
    assert.equal(result.score, 72, '80*0.6 + 60*0.4 = 72');
    passed('both succeed → 0.6/0.4 blend = 72');
  }

  // both fail → tool failure
  {
    const result = combineCodeQuality(
      failPartial('lizard crashed'),
      failPartial('jscpd crashed'),
      true,
    );
    assert.equal(result.applicable, true);
    assert.equal(result.score, 0);
    assert.ok(result.message.startsWith('Tool failed:'), 'failure message');
    passed('both fail → tool failure 0');
  }

  // lizard ok, jscpd fail → lizard only
  {
    const result = combineCodeQuality(
      okPartial(70, 'lizard ok'),
      failPartial('jscpd timed out'),
      true,
    );
    assert.equal(result.score, 70, 'lizard-only score');
    assert.ok(result.message.includes('duplication unavailable'), 'notes unavailable portion');
    passed('lizard ok + jscpd fail → lizard score only');
  }

  // jscpd ok, lizard fail → jscpd only
  {
    const result = combineCodeQuality(
      failPartial('lizard timed out'),
      okPartial(55, 'jscpd ok'),
      true,
    );
    assert.equal(result.score, 55, 'jscpd-only score');
    assert.ok(result.message.includes('complexity unavailable'), 'notes unavailable portion');
    passed('jscpd ok + lizard fail → jscpd score only');
  }
}

// ─── combineMaintenance ────────────────────────────────────────────

function testCombineMaintenance(): void {
  console.log('\n[2] combineMaintenance');

  // with scorecard → 0.6/0.4 blend
  // scorecard 80 * 0.6 + api 100 * 0.4 = 48 + 40 = 88
  {
    const recent = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000); // 10 days ago
    const result = combineMaintenance(
      cs('maintenance_community', 80, true, 'Scorecard ok'),
      recent,
      50,
    );
    assert.equal(result.applicable, true);
    assert.equal(result.score, 88, '80*0.6 + 100*0.4 = 88 (recent commit → api=100)');
    passed('with scorecard → 0.6/0.4 blend = 88');
  }

  // without scorecard (null) → API only
  {
    const recent = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);
    const result = combineMaintenance(null, recent, 0);
    assert.equal(result.applicable, true);
    assert.equal(result.score, 100, 'recent commit → api=100, no scorecard');
    passed('null scorecard → API only = 100');
  }

  // scorecard inconclusive (applicable=false) → API only renormalized
  {
    const stale = new Date(Date.now() - 400 * 24 * 60 * 60 * 1000); // 400 days ago
    const result = combineMaintenance(
      cs('maintenance_community', 0, false, 'all inconclusive'),
      stale,
      0,
    );
    assert.equal(result.applicable, true);
    assert.equal(result.score, 20, 'stale repo → api=20');
    passed('inconclusive scorecard → API only = 20 (stale)');
  }

  // stars > 100 bonus → +10
  {
    const recent = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);
    const result = combineMaintenance(null, recent, 200);
    assert.equal(result.score, 100, '100 base + 10 stars capped at 100');
    passed('stars > 100 → +10 bonus (capped at 100)');
  }

  // stale repo, stars < 100 → 20
  {
    const stale = new Date(Date.now() - 400 * 24 * 60 * 60 * 1000);
    const result = combineMaintenance(null, stale, 5);
    assert.equal(result.score, 20, 'stale + low stars → 20');
    passed('stale + low stars → 20');
  }

  // no pushedAt → treated as stale (20)
  {
    const result = combineMaintenance(null, null, 0);
    assert.equal(result.score, 20, 'no pushedAt → 20');
    passed('null pushedAt → 20');
  }
}

// ─── combineCICDDevops ─────────────────────────────────────────────

function testCombineCICDDevops(): void {
  console.log('\n[3] combineCICDDevops');

  // not applicable, no scorecard → N/A
  {
    const fileScore = cs('cicd_devops', 0, false, 'no ci detected');
    const result = combineCICDDevops(null, fileScore, false);
    assert.equal(result.applicable, false);
    assert.equal(result.score, 0);
    passed('not applicable + no scorecard → N/A');
  }

  // scorecard un-N/As the category (sc=true, file=false)
  // scorecard 70 * 0.6 = 42 (file portion unavailable, renormalized to weight=1)
  {
    const fileScore = cs('cicd_devops', 0, false, 'no ci files');
    const scScore = cs('cicd_devops', 70, true, 'Scorecard CI-Tests');
    const result = combineCICDDevops(scScore, fileScore, false);
    assert.equal(result.applicable, true, 'scorecard un-N/As');
    assert.equal(result.score, 70, 'scorecard only (file unavailable) → 70');
    passed('scorecard un-N/As → applicable, scorecard-only = 70');
  }

  // both available → 0.6/0.4 blend
  // scorecard 80 * 0.6 + file 60 * 0.4 = 48 + 24 = 72
  {
    const fileScore = cs('cicd_devops', 60, true, 'CI config, GitHub Actions');
    const scScore = cs('cicd_devops', 80, true, 'Scorecard ok');
    const result = combineCICDDevops(scScore, fileScore, true);
    assert.equal(result.applicable, true);
    assert.equal(result.score, 72, '80*0.6 + 60*0.4 = 72');
    passed('both available → 0.6/0.4 blend = 72');
  }

  // file only, no scorecard → file score
  {
    const fileScore = cs('cicd_devops', 65, true, 'CI config, husky');
    const result = combineCICDDevops(null, fileScore, true);
    assert.equal(result.score, 65, 'file-only score');
    passed('file only → 65');
  }
}

// ─── combineRepoSecurityPosture ────────────────────────────────────

function testCombineRepoSecurityPosture(): void {
  console.log('\n[4] combineRepoSecurityPosture');

  // with scorecard + SECURITY.md
  // scorecard 70 * 0.7 + 100 * 0.3 = 49 + 30 = 79
  {
    const scScore = cs('repo_security_posture', 70, true, 'Scorecard ok');
    const result = combineRepoSecurityPosture(scScore, true);
    assert.equal(result.applicable, true);
    assert.equal(result.score, 79, '70*0.7 + 100*0.3 = 79');
    passed('scorecard + SECURITY.md → 79');
  }

  // no scorecard, SECURITY.md only
  // 0*0.7 (unavailable) + 100*0.3 = 30 (renormalized: 100*1.0 = 100... wait)
  // actually: only SECURITY.md portion available (weight 0.3), renormalized to 100
  {
    const result = combineRepoSecurityPosture(null, true);
    assert.equal(result.applicable, true);
    assert.equal(result.score, 100, 'SECURITY.md only → 100 (renormalized)');
    passed('SECURITY.md only → 100');
  }

  // no scorecard, no SECURITY.md
  // 0 (no security policy) → renormalized = 0
  {
    const result = combineRepoSecurityPosture(null, false);
    assert.equal(result.applicable, true);
    assert.equal(result.score, 0, 'nothing → 0');
    passed('no scorecard + no SECURITY.md → 0');
  }

  // scorecard + no SECURITY.md
  // scorecard 60 * 0.7 + 0 * 0.3 = 42
  {
    const scScore = cs('repo_security_posture', 60, true, 'Scorecard ok');
    const result = combineRepoSecurityPosture(scScore, false);
    assert.equal(result.score, 42, '60*0.7 + 0*0.3 = 42');
    passed('scorecard 60 + no SECURITY.md → 42');
  }
}

// ─── combineWorkflowSecurity ───────────────────────────────────────

function testCombineWorkflowSecurity(): void {
  console.log('\n[5] combineWorkflowSecurity');

  // not applicable → N/A
  {
    const ogScore = cs('workflow_security', 0, false, 'no workflows');
    const result = combineWorkflowSecurity(null, ogScore, false);
    assert.equal(result.applicable, false);
    assert.equal(result.score, 0);
    passed('not applicable → N/A');
  }

  // both available → 0.7/0.3 blend
  // scorecard 80 * 0.7 + opengrep 60 * 0.3 = 56 + 18 = 74
  {
    const scScore = cs('workflow_security', 80, true, 'Scorecard ok');
    const ogScore = cs('workflow_security', 60, true, 'Opengrep: 2 findings');
    const result = combineWorkflowSecurity(scScore, ogScore, true);
    assert.equal(result.applicable, true);
    assert.equal(result.score, 74, '80*0.7 + 60*0.3 = 74');
    passed('both available → 0.7/0.3 blend = 74');
  }

  // scorecard only, opengrep N/A
  // 80 * 0.7 (renormalized to 1.0) = 80
  {
    const scScore = cs('workflow_security', 80, true, 'Scorecard ok');
    const ogScore = cs('workflow_security', 0, false, 'no opengrep findings');
    const result = combineWorkflowSecurity(scScore, ogScore, true);
    assert.equal(result.score, 80, 'scorecard only → 80');
    passed('scorecard only → 80');
  }

  // opengrep only, no scorecard
  // 50 * 0.3 (renormalized to 1.0) = 50
  {
    const ogScore = cs('workflow_security', 50, true, 'Opengrep: 5 findings');
    const result = combineWorkflowSecurity(null, ogScore, true);
    assert.equal(result.score, 50, 'opengrep only → 50');
    passed('opengrep only → 50');
  }

  // both unavailable → tool failure 0
  {
    const ogScore = cs('workflow_security', 0, false, 'no opengrep');
    const result = combineWorkflowSecurity(null, ogScore, true);
    assert.equal(result.applicable, true);
    assert.equal(result.score, 0, 'both unavailable → 0');
    assert.ok(result.message.startsWith('Tool failed:'), 'tool failure message');
    passed('both unavailable → tool failure 0');
  }
}

// ─── Run all ───────────────────────────────────────────────────────

function main(): void {
  console.log('=== Combiner Tests (Issue #15 blending + #14) ===');
  testCombineCodeQuality();
  testCombineMaintenance();
  testCombineCICDDevops();
  testCombineRepoSecurityPosture();
  testCombineWorkflowSecurity();
  console.log('\n=== ALL COMBINER TESTS PASSED ===\n');
}

main();
