import { defineConfig } from 'tsup';

export default defineConfig([
  // Main library export (Node/ESM)
  {
    entry: ['src/index.ts'],
    format: ['esm'],
    dts: true,
    sourcemap: true,
    clean: true,
    outDir: 'dist',
  },
  // Browser-injectable bundle — curated rules (~85 techs, ~24KB)
  {
    entry: ['src/detect.ts'],
    format: ['iife'],
    globalName: 'wappalyzerjs',
    outDir: 'dist',
    noExternal: [/.*/],
    splitting: false,
    minify: true,
    outExtension: () => ({ js: '.bundle.js' }),
  },
  // Browser-injectable bundle — full Wappalyzer DB (~4900 techs)
  {
    entry: ['src/detect-full.ts'],
    format: ['iife'],
    globalName: 'wappalyzerjs',
    outDir: 'dist',
    noExternal: [/.*/],
    splitting: false,
    minify: true,
    outExtension: () => ({ js: '.bundle.js' }),
  },
]);
