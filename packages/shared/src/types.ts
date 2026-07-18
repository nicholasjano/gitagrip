// ─── Status & Enum Types ─────────────────────────────────────────

export type ScanStatus =
  | 'queued'
  | 'in_progress'
  | 'completed'
  | 'failed'
  | 'timeout'
  | 'cancelled';

export type BatchStatus = 'queued' | 'in_progress' | 'completed' | 'failed' | 'cancelled';

export type ScanType = 'repo' | 'user' | 'org';

export type BatchType = 'user' | 'org';

export type Theme = 'dark' | 'light';

export type ScanCategoryName =
  | 'repository_overview'
  | 'maintenance_community'
  | 'documentation_standards'
  | 'security_vulnerabilities'
  | 'exposed_secrets'
  | 'dependency_health'
  | 'code_quality'
  | 'cicd_devops'
  | 'repo_security_posture'
  | 'workflow_security'
  | 'iac_security'
  | 'dockerfile_best_practices'
  | 'container_security';

// ─── Entity Interfaces ──────────────────────────────────────────

export interface User {
  id: string;
  githubId: number;
  username: string;
  email: string | null;
  avatarUrl: string | null;
  accessToken: string;
  emailNotifications: boolean;
  theme: Theme;
  deletedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ScanBatch {
  id: string;
  requestedBy: string;
  type: BatchType;
  target: string;
  status: BatchStatus;
  totalRepos: number;
  completedRepos: number;
  averageScore: string | null;
  showOnLeaderboard: boolean;
  errorMessage: string | null;
  startedAt: Date | null;
  completedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface Scan {
  id: string;
  requestedBy: string | null;
  batchId: string | null;
  githubRepoId: number;
  repoOwner: string;
  repoName: string;
  isPrivate: boolean;
  isFork: boolean;
  defaultBranch: string;
  language: string | null;
  description: string | null;
  stars: number;
  sizeKb: number;
  status: ScanStatus;
  score: number | null;
  showOnLeaderboard: boolean;
  errorMessage: string | null;
  startedAt: Date | null;
  completedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ScanCategory {
  id: string;
  scanId: string;
  category: ScanCategoryName;
  score: string;
  message: string;
  applicable: boolean;
}

// ─── Scoring Tiers ───────────────────────────────────────────────

export type ScoringTier = 'critical' | 'high' | 'standard';

// single source of truth for tier membership (backend weights + frontend badges)
export const CATEGORY_TIERS: Record<ScanCategoryName, ScoringTier> = {
  exposed_secrets: 'critical',
  security_vulnerabilities: 'critical',
  container_security: 'critical',
  workflow_security: 'critical',
  repo_security_posture: 'critical',
  dockerfile_best_practices: 'high',
  iac_security: 'high',
  dependency_health: 'high',
  cicd_devops: 'high',
  code_quality: 'standard',
  maintenance_community: 'standard',
  documentation_standards: 'standard',
  repository_overview: 'standard',
};

export function tierForCategory(category: ScanCategoryName): ScoringTier {
  return CATEGORY_TIERS[category];
}

// ─── Composite Types ─────────────────────────────────────────────

export interface CategoryScores {
  repositoryOverview: number;
  maintenanceCommunity: number;
  documentationStandards: number;
  securityVulnerabilities: number;
  exposedSecrets: number;
  dependencyHealth: number;
  codeQuality: number;
  cicdDevops: number;
  repoSecurityPosture: number;
  workflowSecurity: number;
  iacSecurity: number;
  dockerfileBestPractices: number;
  containerSecurity: number;
}

export interface ScanResult {
  repoId: string;
  owner: string;
  repo: string;
  score: number;
  categories: CategoryScores;
  scannedAt: Date;
  status: ScanStatus;
}

export interface LeaderboardEntry {
  rank: number;
  name: string;
  averageScore: number;
  repoCount: number;
  type: 'repo' | 'user' | 'org';
}
