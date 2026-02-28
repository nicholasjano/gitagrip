import baseConfig from './base.js';

/** @type {import('eslint').Linter.Config[]} */
const nextConfig = [
  ...baseConfig,
  {
    // Next.js specific overrides
  },
];

export default nextConfig;
