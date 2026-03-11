import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['./src/index.ts', './src/worker/index.ts'],
  noExternal: [/@gitagrip/],
  splitting: false,
  bundle: true,
  outDir: './dist',
  clean: true,
  format: 'esm',
  sourcemap: true,
});
