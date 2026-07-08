// temp test: pipeline simulation — mimics scan-processor.ts scoring flow end-to-end
// without DB/Redis/actual tools. tests the wiring: tools → combiners → aggregate → gate.
// run: pnpm --filter @gitagrip/api exec tsx tmp/pipeline-simulation.test.ts

import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'fs/promises';
import { tmpdir } from 'os';
import path from 'path';
import { detectFiles } from '../src/scanner/detect-files.js';
import type { FileManifest } from '../src/scanner/detect-files.js';
import { getCategoryApplicability } from '../src/scanner/applicability.js';
import { combineCodeQuality } from '../src/scanner/scoring/code-quality.js';
import { combineMaintenance } from '../src/scanner/scoring/maintenance.js';
import {
  combineCICDDevops,
  combineRepoSecurityPosture,
  combineWorkflowSecurity,
} from '../src/scanner/scoring/scorecard-categories.js';
import { computeOverallScore } from '../src/scanner/scoring/aggregate.js';
import { scoreRepositoryOverview } from '../src/scanner/scoring/repo-overview.js';
import type { CategoryScore, PartialToolScore } from '../src/scanner/types.js';
import type { ScanCategoryName } from '../src/scanner/applicability.js';

function passed(name: string): void {
  console.log(`  ✓ ${name}`);
}

function cs(
  category: ScanCategoryName,
  score: number,
  applicable: boolean,
  message: string,
  findingCount?: number,
): CategoryScore {
  return { category, score, applicable, message, findingCount };
}

// ─── Simulate a mock FileManifest (avoid filesystem for speed) ─────

function mockManifest(overrides: Partial<FileManifest> = {}): FileManifest {
  return {
    hasDockerfile: false,
    hasDockerCompose: false,
    hasIaCFiles: false,
    hasLockFiles: false,
    hasCIConfig: false,
    hasWorkflowFiles: false,
    hasHusky: false,
    hasPreCommit: false,
    hasCodeowners: false,
    workflowFileCount: 0,
    hasReadme: false,
    hasLicense: false,
    hasContributing: false,
    hasChangelog: false,
    hasCodeOfConduct: false,
    hasSecurityPolicy: false,
    supportedLanguageFiles: 0,
    totalFiles: 0,
    totalSizeKb: 0,
    ...overrides,
  };
}

// ─── Simulate what each tool would produce for a given scenario ────

interface ToolMocks {
  gitleaks: CategoryScore[];
  trivy: CategoryScore[];
  opengrep: CategoryScore[];
  docs: CategoryScore[];
  cicd: CategoryScore[];
  lizard: PartialToolScore;
  jscpd: PartialToolScore;
  scorecard: CategoryScore[] | null;
}

// simulate a "healthy, well-maintained repo with all file types"
// applicability flags follow the manifest, matching real tool behavior
function healthyRepoTools(manifest: FileManifest): ToolMocks {
  const cicdApplicable = manifest.hasCIConfig || manifest.hasHusky || manifest.hasPreCommit;
  return {
    gitleaks: [cs('exposed_secrets', 100, true, 'No exposed secrets detected', 0)],
    trivy: [
      cs('dependency_health', 95, manifest.hasLockFiles, '1 low vuln', 1),
      cs('security_vulnerabilities', 90, true, '1 high vuln', 1),
      cs('iac_security', 100, manifest.hasIaCFiles, 'No findings', 0),
      cs('dockerfile_best_practices', 85, manifest.hasDockerfile, '1 low misconfig', 1),
      cs(
        'container_security',
        100,
        manifest.hasDockerfile || manifest.hasDockerCompose,
        'No findings',
        0,
      ),
    ],
    opengrep: [
      cs('security_vulnerabilities', 88, true, '2 warnings', 2),
      cs('workflow_security', 95, manifest.hasWorkflowFiles, '1 info finding', 1),
    ],
    docs: [
      cs(
        'documentation_standards',
        80,
        true,
        'Found: README, LICENSE; README quality: substantial length',
        2,
      ),
    ],
    // cicd-check returns N/A when no CI files; scorecard can un-N/A it via blend
    cicd: [
      cs(
        'cicd_devops',
        cicdApplicable ? 70 : 0,
        cicdApplicable,
        cicdApplicable
          ? 'CI config, GitHub Actions, CODEOWNERS'
          : 'No CI or DevOps tooling detected',
        cicdApplicable ? 3 : 0,
      ),
    ],
    lizard: {
      score: 85,
      detail: 'Avg complexity: 5.2 CCN, 2.1% functions > 25 CCN',
      failed: false,
      nloc: 4500,
    },
    jscpd: { score: 90, detail: '2.5% duplication (3 clones)', failed: false },
    // scorecard always reports these as applicable (it sees GitHub-side signals)
    scorecard: [
      cs('maintenance_community', 85, true, 'OSSF Scorecard'),
      cs('cicd_devops', 75, true, 'Scorecard CI-Tests'),
      cs('repo_security_posture', 80, true, 'Scorecard'),
      cs('workflow_security', 90, manifest.hasWorkflowFiles, 'Scorecard Branch-Protection'),
    ],
  };
}

// simulate a "repo with critical secrets and many vulnerabilities"
function badRepoTools(manifest: FileManifest): ToolMocks {
  const cicdApplicable = manifest.hasCIConfig || manifest.hasHusky || manifest.hasPreCommit;
  return {
    gitleaks: [cs('exposed_secrets', 0, true, '2 critical secret(s) detected', 2)],
    trivy: [
      cs('dependency_health', 20, manifest.hasLockFiles, '3 critical, 5 high vulns', 8),
      cs('security_vulnerabilities', 0, true, '2 critical vulns', 2),
      cs('iac_security', 100, manifest.hasIaCFiles, 'No findings', 0),
      cs('dockerfile_best_practices', 40, manifest.hasDockerfile, '3 misconfigs', 3),
      cs(
        'container_security',
        50,
        manifest.hasDockerfile || manifest.hasDockerCompose,
        '2 misconfigs',
        2,
      ),
    ],
    opengrep: [
      cs('security_vulnerabilities', 10, true, '5 errors, 10 warnings', 15),
      cs('workflow_security', 30, manifest.hasWorkflowFiles, '3 error findings', 3),
    ],
    docs: [cs('documentation_standards', 15, true, 'Found: LICENSE', 1)],
    cicd: [
      cs(
        'cicd_devops',
        cicdApplicable ? 10 : 0,
        cicdApplicable,
        cicdApplicable ? 'CI config only' : 'No CI or DevOps tooling detected',
        cicdApplicable ? 1 : 0,
      ),
    ],
    lizard: {
      score: 40,
      detail: 'Avg complexity: 18.5 CCN, 35% functions > 25 CCN',
      failed: false,
      nloc: 200,
    },
    jscpd: { score: 30, detail: '22% duplication (15 clones)', failed: false },
    scorecard: [
      cs('maintenance_community', 30, true, 'OSSF Scorecard'),
      cs('cicd_devops', 25, true, 'Scorecard CI-Tests'),
      cs('repo_security_posture', 35, true, 'Scorecard'),
      cs('workflow_security', 20, manifest.hasWorkflowFiles, 'Scorecard'),
    ],
  };
}

// simulate "all tools crashed"
function allToolsFailed(manifest: FileManifest): ToolMocks {
  return {
    gitleaks: [cs('exposed_secrets', 0, true, 'Tool failed: gitleaks crashed', 0)],
    trivy: [
      cs('dependency_health', 0, manifest.hasLockFiles, 'Tool failed: trivy timed out', 0),
      cs('security_vulnerabilities', 0, true, 'Tool failed: trivy timed out', 0),
      cs('iac_security', 0, manifest.hasIaCFiles, 'Tool failed: trivy timed out', 0),
      cs('dockerfile_best_practices', 0, manifest.hasDockerfile, 'Tool failed: trivy timed out', 0),
      cs(
        'container_security',
        0,
        manifest.hasDockerfile || manifest.hasDockerCompose,
        'Tool failed: trivy timed out',
        0,
      ),
    ],
    opengrep: [
      cs('security_vulnerabilities', 0, true, 'Tool failed: opengrep crashed', 0),
      cs('workflow_security', 0, manifest.hasWorkflowFiles, 'Tool failed: opengrep crashed', 0),
    ],
    docs: [cs('documentation_standards', 0, true, 'Tool failed: docs-check crashed', 0)],
    cicd: [cs('cicd_devops', 0, true, 'Tool failed: cicd-check crashed', 0)],
    lizard: { score: 0, detail: '', failed: true, failureReason: 'lizard crashed' },
    jscpd: { score: 0, detail: '', failed: true, failureReason: 'jscpd crashed' },
    scorecard: null,
  };
}

// ─── Replicate scan-processor's scoring flow (lines 160-279) ───────

interface ScanRow {
  stars: number;
  sizeKb: number;
  language: string | null;
  isFork: boolean;
  description: string | null;
  pushedAt: Date | null;
}

function simulateScoringFlow(
  manifest: FileManifest,
  tools: ToolMocks,
  scanRow: ScanRow,
): {
  overallScore: number;
  categories: CategoryScore[];
  applicableCount: number;
  naCount: number;
  leaderboardEligible: boolean;
  showOnLeaderboard: boolean;
  tiny: boolean;
} {
  const applicability = getCategoryApplicability(manifest);

  // Phase B: gitleaks, lizard, jscpd, docs, cicd
  const categoryScores: CategoryScore[] = [];
  categoryScores.push(...tools.gitleaks);
  categoryScores.push(combineCodeQuality(tools.lizard, tools.jscpd, applicability.code_quality));
  categoryScores.push(...tools.docs, ...tools.cicd);

  // Phase C: trivy
  categoryScores.push(...tools.trivy);

  // Phase D: opengrep
  categoryScores.push(...tools.opengrep);

  // Blend step (replaces 4 categories)
  const scorecardByCategory = new Map<string, CategoryScore>();
  for (const s of tools.scorecard ?? []) {
    scorecardByCategory.set(s.category, s);
  }
  const findScore = (cat: ScanCategoryName): CategoryScore =>
    categoryScores.find((s) => s.category === cat) ?? cs(cat, 0, false, 'not yet computed');

  const blended: CategoryScore[] = [
    combineMaintenance(
      scorecardByCategory.get('maintenance_community') ?? null,
      scanRow.pushedAt,
      scanRow.stars,
    ),
    combineCICDDevops(
      scorecardByCategory.get('cicd_devops') ?? null,
      findScore('cicd_devops'),
      applicability.cicd_devops,
    ),
    combineRepoSecurityPosture(
      scorecardByCategory.get('repo_security_posture') ?? null,
      manifest.hasSecurityPolicy,
    ),
    combineWorkflowSecurity(
      scorecardByCategory.get('workflow_security') ?? null,
      findScore('workflow_security'),
      applicability.workflow_security,
    ),
  ];

  const blendedCategories = new Set(blended.map((s) => s.category));
  const nonBlended = categoryScores.filter((s) => !blendedCategories.has(s.category));
  categoryScores.length = 0;
  categoryScores.push(...nonBlended, ...blended);

  // Push repository_overview
  categoryScores.push(
    scoreRepositoryOverview({
      stars: scanRow.stars,
      sizeKb: scanRow.sizeKb,
      language: scanRow.language,
      isFork: scanRow.isFork,
      description: scanRow.description,
    }),
  );

  // Aggregate
  const result = computeOverallScore(categoryScores);

  // Tiny-repo gate
  const tiny =
    manifest.totalFiles < 5 ||
    manifest.supportedLanguageFiles < 1 ||
    (tools.lizard.nloc !== undefined && tools.lizard.nloc < 100);
  const showOnLeaderboard = result.leaderboardEligible && !tiny;

  return {
    overallScore: result.overallScore,
    categories: result.categories,
    applicableCount: result.applicableCount,
    naCount: result.naCount,
    leaderboardEligible: result.leaderboardEligible,
    showOnLeaderboard,
    tiny,
  };
}

// ─── Test scenarios ────────────────────────────────────────────────

function testHealthyRepoAllFiles(): void {
  console.log('\n[1] Healthy repo with all file types');

  const manifest = mockManifest({
    hasDockerfile: true,
    hasDockerCompose: true,
    hasIaCFiles: true,
    hasLockFiles: true,
    hasCIConfig: true,
    hasWorkflowFiles: true,
    hasHusky: true,
    hasCodeowners: true,
    workflowFileCount: 3,
    hasReadme: true,
    hasLicense: true,
    hasContributing: true,
    hasSecurityPolicy: true,
    supportedLanguageFiles: 50,
    totalFiles: 120,
    totalSizeKb: 5000,
  });

  const scanRow: ScanRow = {
    stars: 250,
    sizeKb: 5000,
    language: 'TypeScript',
    isFork: false,
    description: 'A well-maintained project',
    pushedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000),
  };

  const result = simulateScoringFlow(manifest, healthyRepoTools(manifest), scanRow);

  assert.equal(result.categories.length, 13, 'all 13 categories present');
  assert.equal(result.applicableCount, 13, 'all applicable (all files present)');
  assert.equal(result.naCount, 0, 'no N/A');
  assert.equal(result.leaderboardEligible, true);
  assert.equal(result.tiny, false, 'not tiny (120 files, 4500 NLOC)');
  assert.equal(result.showOnLeaderboard, true);
  assert.ok(
    result.overallScore > 70,
    `healthy repo should score well (got ${result.overallScore})`,
  );

  // verify no duplicate categories
  const catSet = new Set(result.categories.map((c) => c.category));
  assert.equal(catSet.size, 13, 'no duplicate categories');

  passed(`healthy repo → score ${result.overallScore}, 13/13 applicable, on leaderboard`);
}

function testMinimalRepoNoOptionalFiles(): void {
  console.log('\n[2] Minimal repo (no Docker, no IaC, no lockfiles, no CI)');

  const manifest = mockManifest({
    supportedLanguageFiles: 3,
    totalFiles: 10,
    totalSizeKb: 100,
  });

  const scanRow: ScanRow = {
    stars: 2,
    sizeKb: 100,
    language: 'Python',
    isFork: false,
    description: 'A small project',
    pushedAt: new Date(Date.now() - 20 * 24 * 60 * 60 * 1000),
  };

  const tools = healthyRepoTools(manifest);
  const result = simulateScoringFlow(manifest, tools, scanRow);

  assert.equal(result.categories.length, 13, 'all 13 categories present');
  // 6 always-applicable + code_quality (3 source files) + cicd_devops (scorecard un-N/As) = 8
  assert.equal(
    result.applicableCount,
    8,
    '8 applicable (6 always + code_quality + cicd via scorecard)',
  );
  assert.equal(result.naCount, 5, '5 N/A (dependency, workflow, iac, dockerfile, container)');
  assert.equal(result.leaderboardEligible, true, '8 >= 6');
  assert.equal(result.tiny, false, '10 files, 3 source files → not tiny');
  assert.equal(result.showOnLeaderboard, true);

  // verify N/A categories have canonical messages
  const naCats = result.categories.filter((c) => !c.applicable);
  for (const na of naCats) {
    assert.ok(na.message.startsWith('N/A -'), `${na.category} has canonical N/A message`);
    assert.equal(na.score, 0, `${na.category} N/A score is 0`);
  }

  passed(
    `minimal repo → score ${result.overallScore}, ${result.applicableCount} applicable, ${result.naCount} N/A, on leaderboard`,
  );
}

function testBadRepo(): void {
  console.log('\n[3] Bad repo (secrets + vulns + poor quality)');

  const manifest = mockManifest({
    hasDockerfile: true,
    hasLockFiles: true,
    hasWorkflowFiles: true,
    hasCIConfig: true,
    supportedLanguageFiles: 20,
    totalFiles: 30,
    totalSizeKb: 2000,
  });

  const scanRow: ScanRow = {
    stars: 1,
    sizeKb: 2000,
    language: 'JavaScript',
    isFork: true,
    description: '',
    pushedAt: new Date(Date.now() - 500 * 24 * 60 * 60 * 1000), // very stale
  };

  const result = simulateScoringFlow(manifest, badRepoTools(manifest), scanRow);

  assert.equal(result.categories.length, 13);
  assert.ok(result.overallScore < 40, `bad repo should score low (got ${result.overallScore})`);
  assert.equal(result.leaderboardEligible, true, 'still eligible by category count');
  assert.equal(result.tiny, false);
  assert.equal(result.showOnLeaderboard, true, 'eligible but will rank low');

  // exposed_secrets should be 0 (critical secrets)
  const secrets = result.categories.find((c) => c.category === 'exposed_secrets')!;
  assert.equal(secrets.score, 0, 'critical secrets → 0');

  // security_vulnerabilities should be worst of trivy(0) and opengrep(10) = 0
  const vulns = result.categories.find((c) => c.category === 'security_vulnerabilities')!;
  assert.equal(vulns.score, 0, 'worst of 0 and 10 = 0');

  passed(`bad repo → score ${result.overallScore}, secrets=0, vulns=0 (dedup worst-wins)`);
}

function testTinyRepoExcluded(): void {
  console.log('\n[4] Tiny repo excluded from leaderboard');

  // < 5 files
  {
    const manifest = mockManifest({
      supportedLanguageFiles: 1,
      totalFiles: 3,
      totalSizeKb: 5,
    });

    const scanRow: ScanRow = {
      stars: 0,
      sizeKb: 5,
      language: 'Go',
      isFork: false,
      description: 'tiny',
      pushedAt: new Date(),
    };

    const result = simulateScoringFlow(manifest, healthyRepoTools(manifest), scanRow);

    assert.equal(result.tiny, true, '3 files → tiny');
    assert.equal(result.showOnLeaderboard, false, 'tiny → excluded from leaderboard');
    passed('3 files → tiny → excluded');
  }

  // 0 supported language files (Lizard skipped, NLOC unknown)
  {
    const manifest = mockManifest({
      supportedLanguageFiles: 0,
      totalFiles: 50,
      totalSizeKb: 500,
    });

    const scanRow: ScanRow = {
      stars: 5,
      sizeKb: 500,
      language: null,
      isFork: false,
      description: 'asset repo',
      pushedAt: new Date(),
    };

    const tools = healthyRepoTools(manifest);
    tools.lizard = { score: 0, detail: '', failed: true, failureReason: 'skipped' };
    const result = simulateScoringFlow(manifest, tools, scanRow);

    assert.equal(result.tiny, true, '0 supported files → tiny (hole plugged)');
    assert.equal(result.showOnLeaderboard, false, 'no code files → excluded');
    passed('50 asset files, 0 source → tiny (hole plugged) → excluded');
  }

  // NLOC < 100
  {
    const manifest = mockManifest({
      supportedLanguageFiles: 2,
      totalFiles: 10,
      totalSizeKb: 50,
    });

    const scanRow: ScanRow = {
      stars: 0,
      sizeKb: 50,
      language: 'Ruby',
      isFork: false,
      description: 'small',
      pushedAt: new Date(),
    };

    const tools = healthyRepoTools(manifest);
    tools.lizard = { score: 100, detail: 'trivial', failed: false, nloc: 42 };
    const result = simulateScoringFlow(manifest, tools, scanRow);

    assert.equal(result.tiny, true, 'NLOC 42 < 100 → tiny');
    assert.equal(result.showOnLeaderboard, false);
    passed('NLOC 42 < 100 → tiny → excluded');
  }

  // boundary: exactly 5 files, 1 source file, NLOC 100 → NOT tiny
  {
    const manifest = mockManifest({
      supportedLanguageFiles: 1,
      totalFiles: 5,
      totalSizeKb: 100,
    });

    const scanRow: ScanRow = {
      stars: 0,
      sizeKb: 100,
      language: 'C',
      isFork: false,
      description: 'boundary',
      pushedAt: new Date(),
    };

    const tools = healthyRepoTools(manifest);
    tools.lizard = { score: 100, detail: 'ok', failed: false, nloc: 100 };
    const result = simulateScoringFlow(manifest, tools, scanRow);

    assert.equal(result.tiny, false, '5 files, 1 source, 100 NLOC → not tiny (boundaries)');
    assert.equal(result.showOnLeaderboard, true);
    passed('boundary (5 files / 1 source / 100 NLOC) → not tiny');
  }
}

function testSecurityVulnsDedupInPipeline(): void {
  console.log('\n[5] security_vulnerabilities dedup in full pipeline');

  const manifest = mockManifest({
    supportedLanguageFiles: 10,
    totalFiles: 20,
    totalSizeKb: 500,
  });

  const scanRow: ScanRow = {
    stars: 10,
    sizeKb: 500,
    language: 'TypeScript',
    isFork: false,
    description: 'test',
    pushedAt: new Date(),
  };

  const tools = healthyRepoTools(manifest);
  // trivy says 90, opengrep says 88 → worst = 88
  const result = simulateScoringFlow(manifest, tools, scanRow);

  const vulns = result.categories.find((c) => c.category === 'security_vulnerabilities')!;
  assert.equal(vulns.score, 88, 'worst of trivy(90) and opengrep(88) = 88');

  // verify only ONE security_vulnerabilities row (not two)
  const vulnsCount = result.categories.filter(
    (c) => c.category === 'security_vulnerabilities',
  ).length;
  assert.equal(vulnsCount, 1, 'only one security_vulnerabilities row after dedup');

  passed('pipeline dedup: trivy(90) + opengrep(88) → one row scoring 88');
}

function testToolFailureDoesNotNukeScore(): void {
  console.log('\n[6] Tool failure does not nuke overall score');

  const manifest = mockManifest({
    hasDockerfile: true,
    hasLockFiles: true,
    supportedLanguageFiles: 15,
    totalFiles: 40,
    totalSizeKb: 1000,
  });

  const scanRow: ScanRow = {
    stars: 50,
    sizeKb: 1000,
    language: 'Rust',
    isFork: false,
    description: 'solid repo',
    pushedAt: new Date(),
  };

  // trivy crashes (0, tool-failed) but opengrep succeeds (85)
  const tools = healthyRepoTools(manifest);
  tools.trivy = [
    cs('dependency_health', 0, manifest.hasLockFiles, 'Tool failed: trivy timed out', 0),
    cs('security_vulnerabilities', 0, true, 'Tool failed: trivy timed out', 0),
    cs('iac_security', 0, manifest.hasIaCFiles, 'Tool failed: trivy timed out', 0),
    cs('dockerfile_best_practices', 0, manifest.hasDockerfile, 'Tool failed: trivy timed out', 0),
    cs('container_security', 0, manifest.hasDockerfile, 'Tool failed: trivy timed out', 0),
  ];
  // opengrep says security_vulnerabilities = 85
  tools.opengrep = [
    cs('security_vulnerabilities', 85, true, 'No findings', 0),
    cs('workflow_security', 90, manifest.hasWorkflowFiles, 'clean', 0),
  ];

  const result = simulateScoringFlow(manifest, tools, scanRow);

  const vulns = result.categories.find((c) => c.category === 'security_vulnerabilities')!;
  assert.equal(vulns.score, 85, 'opengrep 85 beats trivy failure 0');

  // overall should still be decent — not nuked by trivy crash
  assert.ok(
    result.overallScore > 50,
    `trivy crash shouldn't tank score (got ${result.overallScore})`,
  );

  passed(`trivy crash → vulns=85 (opengrep), overall=${result.overallScore} (not nuked)`);
}

function test13UniqueCategoriesAlways(): void {
  console.log('\n[7] Always produces exactly 13 unique categories');

  const scenarios = [
    {
      name: 'all files',
      manifest: mockManifest({
        hasDockerfile: true,
        hasLockFiles: true,
        hasIaCFiles: true,
        hasWorkflowFiles: true,
        hasCIConfig: true,
        supportedLanguageFiles: 10,
        totalFiles: 50,
      }),
    },
    {
      name: 'no optional files',
      manifest: mockManifest({ supportedLanguageFiles: 5, totalFiles: 15 }),
    },
    {
      name: 'only source files',
      manifest: mockManifest({ supportedLanguageFiles: 8, totalFiles: 8 }),
    },
    { name: 'empty-ish', manifest: mockManifest({ totalFiles: 2 }) },
  ];

  const scanRow: ScanRow = {
    stars: 10,
    sizeKb: 500,
    language: 'Python',
    isFork: false,
    description: 'test',
    pushedAt: new Date(),
  };

  for (const { name, manifest } of scenarios) {
    const tools = healthyRepoTools(manifest);
    const result = simulateScoringFlow(manifest, tools, scanRow);

    assert.equal(result.categories.length, 13, `${name}: 13 categories`);

    const catSet = new Set(result.categories.map((c) => c.category));
    assert.equal(catSet.size, 13, `${name}: 13 unique categories`);

    // verify all 13 expected categories are present
    const expected: ScanCategoryName[] = [
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
    for (const cat of expected) {
      assert.ok(catSet.has(cat), `${name}: ${cat} present`);
    }
  }

  passed('all scenarios produce exactly 13 unique categories');
}

// ─── detectFiles with real temp directory ──────────────────────────

async function testDetectFiles(): Promise<void> {
  console.log('\n[8] detectFiles with temp directory');

  const dir = await mkdtemp(path.join(tmpdir(), 'gitagrip-test-'));

  try {
    // create a realistic repo structure
    await writeFile(
      path.join(dir, 'README.md'),
      '# Test\n\nSome content here that is long enough.',
    );
    await writeFile(path.join(dir, 'LICENSE'), 'MIT License');
    await writeFile(path.join(dir, 'package-lock.json'), '{}');
    await writeFile(path.join(dir, 'index.ts'), 'console.log("hello");');
    await writeFile(path.join(dir, 'utils.py'), 'def foo(): pass');
    await mkdir(path.join(dir, '.github', 'workflows'), { recursive: true });
    await writeFile(path.join(dir, '.github', 'workflows', 'ci.yml'), 'name: CI');
    await writeFile(path.join(dir, 'Dockerfile'), 'FROM node:20');
    await writeFile(path.join(dir, 'SECURITY.md'), '# Security Policy');
    await mkdir(path.join(dir, '.husky'), { recursive: true });
    await writeFile(path.join(dir, '.husky', 'pre-commit'), 'npm test');

    const manifest = await detectFiles(dir);

    assert.equal(manifest.hasDockerfile, true, 'Dockerfile detected');
    assert.equal(manifest.hasLockFiles, true, 'lock file detected');
    assert.equal(manifest.hasWorkflowFiles, true, 'workflow file detected');
    assert.equal(manifest.hasCIConfig, true, 'CI config detected');
    assert.equal(manifest.hasHusky, true, 'husky detected');
    assert.equal(manifest.hasReadme, true, 'README detected');
    assert.equal(manifest.hasLicense, true, 'LICENSE detected');
    assert.equal(manifest.hasSecurityPolicy, true, 'SECURITY.md detected');
    assert.ok(manifest.supportedLanguageFiles >= 2, 'at least 2 source files (ts + py)');
    assert.ok(manifest.totalFiles >= 9, 'at least 9 total files');
    assert.equal(manifest.workflowFileCount, 1, '1 workflow file');

    passed(
      `detectFiles: ${manifest.totalFiles} files, ${manifest.supportedLanguageFiles} source, all flags correct`,
    );

    // test applicability from manifest
    const applicability = getCategoryApplicability(manifest);
    assert.equal(applicability.dockerfile_best_practices, true, 'dockerfile applicable');
    assert.equal(applicability.container_security, true, 'container applicable');
    assert.equal(applicability.dependency_health, true, 'dependency_health applicable');
    assert.equal(applicability.code_quality, true, 'code_quality applicable');
    assert.equal(applicability.cicd_devops, true, 'cicd_devops applicable');
    assert.equal(applicability.workflow_security, true, 'workflow_security applicable');
    assert.equal(applicability.repository_overview, true, 'always applicable');
    assert.equal(applicability.exposed_secrets, true, 'always applicable');
    assert.equal(applicability.iac_security, false, 'no IaC files → N/A');

    passed('getCategoryApplicability: correct flags from real file detection');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

// ─── Run all ───────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log('=== Pipeline Simulation Tests (End-to-End Scoring Flow) ===');
  testHealthyRepoAllFiles();
  testMinimalRepoNoOptionalFiles();
  testBadRepo();
  testTinyRepoExcluded();
  testSecurityVulnsDedupInPipeline();
  testToolFailureDoesNotNukeScore();
  test13UniqueCategoriesAlways();
  await testDetectFiles();
  console.log('\n=== ALL PIPELINE SIMULATION TESTS PASSED ===\n');
}

main().catch((err) => {
  console.error('\n❌ TEST FAILED:', err);
  process.exit(1);
});
