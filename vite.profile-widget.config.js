import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

export default defineConfig({
  plugins: [react()],
  publicDir: false,
  define: { 'process.env.NODE_ENV': JSON.stringify('production') },
  build: {
    outDir: 'public',
    emptyOutDir: false,
    lib: {
      entry: resolve(__dirname, 'frontend/profileWidget/main.jsx'),
      name: 'EcosystemProfileWidget',
      formats: ['iife'],
      fileName: () => 'profile-widget.js',
    },
    rollupOptions: { output: { inlineDynamicImports: true } },
  },
});
