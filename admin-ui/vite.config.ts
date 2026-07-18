import { defineConfig } from 'vite';

// Served by the Rust backend at /admin (rust-embed). `base: '/admin/'` makes the
// built asset URLs absolute under /admin/assets/ so they resolve regardless of the
// trailing slash. Preact JSX via esbuild (no plugin, keeps the toolchain tiny).
export default defineConfig({
  base: '/admin/',
  build: {
    outDir: 'dist',
    target: 'es2022',
    emptyOutDir: true,
    assetsDir: 'assets',
  },
  esbuild: {
    jsx: 'automatic',
    jsxImportSource: 'preact',
  },
});
