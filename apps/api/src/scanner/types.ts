// shared scanner result types

import type { ScanCategoryName } from './applicability.js';
import type { ScanLogger } from './logger.js';

export interface CategoryScore {
  category: ScanCategoryName;
  score: number;
  applicable: boolean;
  message: string;
  findingCount?: number;
}

export interface ToolRunContext {
  repoDir: string;
  scanId: string;
  logger: ScanLogger;
  signal?: AbortSignal;
}

export interface PartialToolScore {
  score: number;
  detail: string;
  failed: boolean;
  failureReason?: string;
  nloc?: number;
}

export function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function toolFailedScores(categories: ScanCategoryName[], reason: string): CategoryScore[] {
  return categories.map((category) => ({
    category,
    score: 0,
    applicable: true,
    message: `Tool failed: ${reason}`,
    findingCount: 0,
  }));
}

export function notApplicableScore(category: ScanCategoryName, reason: string): CategoryScore {
  return {
    category,
    score: 0,
    applicable: false,
    message: reason,
    findingCount: 0,
  };
}

export function isToolFailure(score: CategoryScore): boolean {
  return score.message.startsWith('Tool failed:');
}

export function hasUsableCategoryData(scores: CategoryScore[]): boolean {
  return scores.some((score) => score.applicable && !isToolFailure(score));
}
