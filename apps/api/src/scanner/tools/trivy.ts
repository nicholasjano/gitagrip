// trivy runner and parser — dependency, security, iac, docker, container categories

import { readFile, rm } from 'fs/promises';
import path from 'path';
import type { FileManifest } from '../detect-files.js';
import { runTool } from '../run-tool.js';
import {
  clampScore,
  notApplicableScore,
  type CategoryScore,
  type ToolRunContext,
} from '../types.js';
import type { ScanCategoryName } from '../applicability.js';

const REPORT_DIR = '/tmp';

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

interface TrivyVulnerability {
  VulnerabilityID?: string;
  Severity?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
}

interface TrivyMisconfiguration {
  ID?: string;
  Severity?: string;
  Title?: string;
  Type?: string;
  Status?: string;
}

interface TrivyResult {
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfiguration[];
}

interface TrivyReport {
  Results?: TrivyResult[];
}

interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

function buildFailureScores(manifest: FileManifest, reason: string): CategoryScore[] {
  return [
    manifest.hasLockFiles
      ? {
          category: 'dependency_health',
          score: 0,
          applicable: true,
          message: `Tool failed: ${reason}`,
          findingCount: 0,
        }
      : notApplicableScore('dependency_health', 'No lock files detected'),
    {
      category: 'security_vulnerabilities',
      score: 0,
      applicable: true,
      message: `Tool failed: ${reason}`,
      findingCount: 0,
    },
    manifest.hasIaCFiles
      ? {
          category: 'iac_security',
          score: 0,
          applicable: true,
          message: `Tool failed: ${reason}`,
          findingCount: 0,
        }
      : notApplicableScore('iac_security', 'No IaC files detected'),
    manifest.hasDockerfile
      ? {
          category: 'dockerfile_best_practices',
          score: 0,
          applicable: true,
          message: `Tool failed: ${reason}`,
          findingCount: 0,
        }
      : notApplicableScore('dockerfile_best_practices', 'No Dockerfile detected'),
    manifest.hasDockerfile || manifest.hasDockerCompose
      ? {
          category: 'container_security',
          score: 0,
          applicable: true,
          message: `Tool failed: ${reason}`,
          findingCount: 0,
        }
      : notApplicableScore('container_security', 'No Docker or compose files detected'),
  ];
}

function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

function normalizeSeverity(value?: string): keyof SeverityCounts | null {
  const upper = (value ?? 'UNKNOWN').toUpperCase();
  if (upper === 'CRITICAL') return 'critical';
  if (upper === 'HIGH') return 'high';
  if (upper === 'MEDIUM') return 'medium';
  if (upper === 'LOW') return 'low';
  return null;
}

function addSeverity(counts: SeverityCounts, severity?: string): void {
  const key = normalizeSeverity(severity);
  if (key) counts[key]++;
}

function scoreFromCounts(counts: SeverityCounts): number {
  const penalty = counts.critical * 20 + counts.high * 10 + counts.medium * 3 + counts.low * 1;
  return clampScore(100 - penalty);
}

function buildScore(
  category: ScanCategoryName,
  counts: SeverityCounts,
  applicable: boolean,
  naReason: string,
): CategoryScore {
  if (!applicable) {
    return notApplicableScore(category, naReason);
  }

  const total = counts.critical + counts.high + counts.medium + counts.low;

  return {
    category,
    score: scoreFromCounts(counts),
    applicable: true,
    message: total === 0 ? 'No findings detected' : `${total} finding(s) detected`,
    findingCount: total,
  };
}

function isIacType(type?: string): boolean {
  const normalized = (type ?? '').toLowerCase();
  return (
    normalized === 'terraform' || normalized === 'cloudformation' || normalized === 'kubernetes'
  );
}

function isContainerMisconfig(type?: string, title?: string): boolean {
  const normalizedType = (type ?? '').toLowerCase();
  const normalizedTitle = (title ?? '').toLowerCase();
  if (normalizedType === 'dockerfile') return false;
  return (
    normalizedType.includes('docker-compose') ||
    normalizedTitle.includes('docker-compose') ||
    normalizedTitle.includes('compose')
  );
}

function parseReport(raw: string): TrivyReport {
  if (!raw.trim()) return {};
  const parsed = JSON.parse(raw) as TrivyReport;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  if (!Array.isArray(parsed.Results)) return { ...parsed, Results: undefined };
  return parsed;
}

export async function runTrivy(
  ctx: ToolRunContext & { manifest: FileManifest },
): Promise<CategoryScore[]> {
  const { repoDir, scanId, manifest, logger, signal } = ctx;
  const reportPath = path.join(REPORT_DIR, `trivy-${scanId}.json`);

  try {
    const result = await runTool({
      cmd: 'trivy',
      args: [
        'fs',
        '--scanners',
        'vuln,misconfig,secret',
        '--format',
        'json',
        '--output',
        reportPath,
        '--timeout',
        '5m',
        repoDir,
      ],
      label: 'trivy',
      logger,
      signal,
    });

    if (result.status === 'timeout') {
      return buildFailureScores(manifest, 'trivy timed out');
    }
    if (result.status === 'crash') {
      return buildFailureScores(manifest, 'trivy crashed');
    }

    let report: TrivyReport;
    try {
      const raw = await readFile(reportPath, 'utf8');
      report = parseReport(raw);
    } catch {
      return buildFailureScores(manifest, 'trivy JSON parse error');
    }

    const dependencyCounts = emptyCounts();
    const securityCounts = emptyCounts();
    const iacCounts = emptyCounts();
    const dockerfileCounts = emptyCounts();
    const containerCounts = emptyCounts();

    for (const entry of report.Results ?? []) {
      for (const vuln of entry.Vulnerabilities ?? []) {
        addSeverity(dependencyCounts, vuln.Severity);
        const sev = (vuln.Severity ?? '').toUpperCase() as Severity;
        if (sev === 'CRITICAL' || sev === 'HIGH') {
          addSeverity(securityCounts, vuln.Severity);
        }
      }

      for (const misconfig of entry.Misconfigurations ?? []) {
        if ((misconfig.Status ?? '').toUpperCase() !== 'FAIL') continue;

        const type = misconfig.Type;
        const title = misconfig.Title;

        if (isIacType(type)) {
          addSeverity(iacCounts, misconfig.Severity);
        }
        if ((type ?? '').toLowerCase() === 'dockerfile') {
          addSeverity(dockerfileCounts, misconfig.Severity);
        }
        if (isContainerMisconfig(type, title)) {
          addSeverity(containerCounts, misconfig.Severity);
        }
      }
    }

    return [
      buildScore(
        'dependency_health',
        dependencyCounts,
        manifest.hasLockFiles,
        'No lock files detected',
      ),
      buildScore('security_vulnerabilities', securityCounts, true, 'N/A'),
      buildScore('iac_security', iacCounts, manifest.hasIaCFiles, 'No IaC files detected'),
      buildScore(
        'dockerfile_best_practices',
        dockerfileCounts,
        manifest.hasDockerfile,
        'No Dockerfile detected',
      ),
      buildScore(
        'container_security',
        containerCounts,
        manifest.hasDockerfile || manifest.hasDockerCompose,
        'No Docker or compose files detected',
      ),
    ];
  } finally {
    await rm(reportPath, { force: true });
  }
}
