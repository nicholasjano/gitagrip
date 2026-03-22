import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    './src/index.ts',
    './src/worker/index.ts',
    './src/worker/scan-processor.ts',
    './src/worker/batch-processor.ts',
  ],
  noExternal: [/@gitagrip/],
  splitting: false,
  bundle: true,
  outDir: './dist',
  clean: true,
  format: 'esm',
  sourcemap: true,
});
