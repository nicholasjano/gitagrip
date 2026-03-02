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
