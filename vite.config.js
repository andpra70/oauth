import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

export default defineConfig({
  plugins: [react()],
  publicDir: false,
  build: {
    outDir: 'public/assets',
    emptyOutDir: false,
    rollupOptions: {
      input: {
        app: resolve(__dirname, 'frontend/app/main.jsx'),
        authWidget: resolve(__dirname, 'frontend/authWidget/main.jsx'),
        'oidc-ui': resolve(__dirname, 'frontend/oidc-ui/main.jsx'),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'chunks/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
});
