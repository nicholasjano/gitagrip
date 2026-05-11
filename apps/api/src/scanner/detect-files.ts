// extracts files from clone in temp directory as a list, exports detectFiles for scan-processor.ts

import { lstat, opendir } from 'fs/promises';
import path from 'path';

export interface FileManifest {
  hasDockerfile: boolean;
  hasDockerCompose: boolean;
  hasIaCFiles: boolean;
  hasLockFiles: boolean;
  hasCIConfig: boolean;
  hasWorkflowFiles: boolean;
  hasReadme: boolean;
  hasLicense: boolean;
  hasContributing: boolean;
  hasChangelog: boolean;
  hasCodeOfConduct: boolean;
  hasSecurityPolicy: boolean;
  supportedLanguageFiles: number;
  totalFiles: number;
  totalSizeKb: number;
}

// extensions we consider "real source code" for code quality scoring
const SUPPORTED_LANGUAGE_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.rb',
  '.go',
  '.rs',
  '.java',
  '.kt',
  '.swift',
  '.cpp',
  '.c',
  '.cs',
  '.php',
]);

const LOCK_FILES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'go.sum',
  'Cargo.lock',
  'Gemfile.lock',
  'requirements.txt',
  'poetry.lock',
  'composer.lock',
  'pubspec.lock',
  'Pipfile.lock',
]);

const DOCKERFILE_PATTERN = /^(dockerfile|.*\.dockerfile)$/i;
const DOCKER_COMPOSE_PATTERN = /^(docker-compose|compose)(\..*)?\.ya?ml$/i;

// iac: terraform, cloudformation, k8s manifests
const IAC_PATTERN = /\.(tf|tfvars)$|cloudformation.*\.ya?ml$|^(k8s|kubernetes|manifests)\//i;

const CI_FILES = new Set(['Jenkinsfile', '.gitlab-ci.yml']);
const CI_DIRS = ['.github/workflows', '.circleci'];

export async function detectFiles(repoDir: string): Promise<FileManifest> {
  const manifest: FileManifest = {
    hasDockerfile: false,
    hasDockerCompose: false,
    hasIaCFiles: false,
    hasLockFiles: false,
    hasCIConfig: false,
    hasWorkflowFiles: false,
    hasReadme: false,
    hasLicense: false,
    hasContributing: false,
    hasChangelog: false,
    hasCodeOfConduct: false,
    hasSecurityPolicy: false,
    supportedLanguageFiles: 0,
    totalFiles: 0,
    totalSizeKb: 0,
  };

  let totalBytes = 0;

  async function walk(dirPath: string): Promise<void> {
    const handle = await opendir(dirPath);
    try {
      for await (const entry of handle) {
        if (entry.name === '.git') continue;

        const fullPath = path.join(dirPath, entry.name);
        let stats;
        try {
          // lstat so symlinks are never followed during traversal
          stats = await lstat(fullPath);
        } catch {
          continue;
        }

        if (stats.isSymbolicLink()) continue;

        if (stats.isDirectory()) {
          await walk(fullPath);
          continue;
        }
        if (!stats.isFile()) continue;

        const relativePath = path.relative(repoDir, fullPath);
        if (relativePath.startsWith('.git/') || relativePath === '.git') continue;

        const fileNameRaw = entry.name;
        const fileName = fileNameRaw.toLowerCase();
        const fileSize = stats.size;

        manifest.totalFiles++;
        totalBytes += fileSize;

        if (DOCKERFILE_PATTERN.test(fileNameRaw)) manifest.hasDockerfile = true;

        if (DOCKER_COMPOSE_PATTERN.test(fileNameRaw)) manifest.hasDockerCompose = true;

        if (IAC_PATTERN.test(relativePath)) manifest.hasIaCFiles = true;

        if (LOCK_FILES.has(fileNameRaw)) manifest.hasLockFiles = true;

        if (
          relativePath.startsWith('.github/workflows/') &&
          (fileName.endsWith('.yml') || fileName.endsWith('.yaml'))
        ) {
          manifest.hasCIConfig = true;
          manifest.hasWorkflowFiles = true;
        }

        if (CI_FILES.has(fileNameRaw)) manifest.hasCIConfig = true;
        if (CI_DIRS.some((d) => relativePath.startsWith(d + '/'))) manifest.hasCIConfig = true;

        const dir = path.dirname(relativePath);
        const isTopLevelOrGithub = dir === '.' || dir === '.github';

        if (isTopLevelOrGithub) {
          if (/^readme(\..+)?$/i.test(fileNameRaw)) manifest.hasReadme = true;
          if (/^(license|copying)(\..+)?$/i.test(fileNameRaw)) manifest.hasLicense = true;
          if (/^contributing(\..+)?$/i.test(fileNameRaw)) manifest.hasContributing = true;
          if (/^(changelog|changes|history)(\..+)?$/i.test(fileNameRaw))
            manifest.hasChangelog = true;
          if (/^code[-_]?of[-_]?conduct(\..+)?$/i.test(fileNameRaw))
            manifest.hasCodeOfConduct = true;
          if (/^security(\..+)?$/i.test(fileNameRaw)) manifest.hasSecurityPolicy = true;
        }

        const ext = path.extname(fileName);
        if (SUPPORTED_LANGUAGE_EXTENSIONS.has(ext)) manifest.supportedLanguageFiles++;
      }
    } finally {
      // opendir handle auto-closes after iteration
    }
  }

  await walk(repoDir);

  manifest.totalSizeKb = Math.round(totalBytes / 1024);

  return manifest;
}
