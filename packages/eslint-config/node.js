import baseConfig from './base.js';

/** @type {import('eslint').Linter.Config[]} */
const nodeConfig = [
  ...baseConfig,
  {
    // Node/Express specific overrides
  },
];

export default nodeConfig;
