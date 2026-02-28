import baseConfig from '@gitagrip/eslint-config/base';

export default [
  ...baseConfig,
  {
    ignores: ['packages/eslint-config/**', 'packages/typescript-config/**'],
  },
];
