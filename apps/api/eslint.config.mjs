import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import nodeConfig from '@gitagrip/eslint-config/node';

const apiRoot = dirname(fileURLToPath(import.meta.url));

/** @type {import('eslint').Linter.Config[]} */
export default [
  ...nodeConfig,
  {
    // ponytail: scripts share tsconfig.scripts.json (issue #17), not main src-only tsconfig
    files: ['scripts/**/*.ts'],
    languageOptions: {
      parserOptions: {
        projectService: false,
        project: [join(apiRoot, 'tsconfig.scripts.json')],
      },
    },
  },
];
