// pure Node.js CI/CD and DevOps file scorer

import type { CategoryApplicability } from '../applicability.js';
import type { FileManifest } from '../detect-files.js';
import {
  clampScore,
  notApplicableScore,
  type CategoryScore,
  type ToolRunContext,
} from '../types.js';

export async function runCICDCheck(
  ctx: ToolRunContext & { manifest: FileManifest; applicability: CategoryApplicability },
): Promise<CategoryScore[]> {
  const { manifest, applicability } = ctx;

  if (!applicability.cicd_devops) {
    return [notApplicableScore('cicd_devops', 'No CI or DevOps tooling detected')];
  }

  let score = 0;
  const signals: string[] = [];

  if (manifest.hasCIConfig) {
    score += 40;
    signals.push('CI config');
  }
  if (manifest.hasWorkflowFiles) {
    score += 20;
    signals.push('GitHub Actions');
  }
  if (manifest.workflowFileCount >= 2) {
    score += 10;
    signals.push(`${manifest.workflowFileCount} workflows`);
  }
  if (manifest.hasCodeowners) {
    score += 15;
    signals.push('CODEOWNERS');
  }
  if (manifest.hasHusky || manifest.hasPreCommit) {
    score += 15;
    if (manifest.hasHusky) signals.push('husky');
    if (manifest.hasPreCommit) signals.push('pre-commit');
  }

  return [
    {
      category: 'cicd_devops',
      score: clampScore(score),
      applicable: true,
      message: signals.length > 0 ? signals.join(', ') : 'No CI/DevOps signals detected',
      findingCount: signals.length,
    },
  ];
}
