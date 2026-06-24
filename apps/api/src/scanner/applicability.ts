// exports getCategoryApplicability for scan-processor.ts

import type { SCAN_CATEGORY_NAMES } from '../db/schema.js';
import type { FileManifest } from './detect-files.js';

export type ScanCategoryName = (typeof SCAN_CATEGORY_NAMES)[number];

export type CategoryApplicability = Record<ScanCategoryName, boolean>;

/**
 * determines which of the 13 scan categories apply to a given repo
 * based on the files present. false = N/A, true = applicable.
 *
 * always-applicable categories are never skipped regardless of file contents.
 * conditional categories are skipped when the relevant files are absent,
 * since running those tools would produce meaningless scores.
 */
export function getCategoryApplicability(manifest: FileManifest): CategoryApplicability {
  return {
    // always applicable
    repository_overview: true,
    maintenance_community: true,
    documentation_standards: true,
    security_vulnerabilities: true,
    exposed_secrets: true,
    repo_security_posture: true,

    // conditional
    dependency_health: manifest.hasLockFiles,
    code_quality: manifest.supportedLanguageFiles > 0,
    cicd_devops: manifest.hasCIConfig || manifest.hasHusky || manifest.hasPreCommit,
    workflow_security: manifest.hasWorkflowFiles,
    iac_security: manifest.hasIaCFiles,
    dockerfile_best_practices: manifest.hasDockerfile,
    container_security: manifest.hasDockerfile || manifest.hasDockerCompose,
  };
}
