export interface ScanResult {
  repoId: string;
  owner: string;
  repo: string;
  score: number;
  categories: CategoryScores;
  scannedAt: Date;
  status: ScanStatus;
}

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
}

export type ScanStatus = 'queued' | 'in_progress' | 'completed' | 'failed' | 'timeout';

export type ScanType = 'repo' | 'user' | 'org';

export interface User {
  id: string;
  githubId: string;
  username: string;
  email: string | null;
  avatarUrl: string | null;
  createdAt: Date;
}

export interface LeaderboardEntry {
  rank: number;
  name: string;
  averageScore: number;
  repoCount: number;
  type: 'repo' | 'user' | 'org';
}
