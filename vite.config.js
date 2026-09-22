import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

export default defineConfig({
  preview: {
    host: '0.0.0.0',
    allowedHosts: true,
  },
  server: {
    host: '0.0.0.0',
    allowedHosts: true,
  },
  plugins: [react()],
  publicDir: false,
  build: {
    outDir: 'public/assets',
    emptyOutDir: false,
    rollupOptions: {
      input: {
        app: resolve(__dirname, 'frontend/app/main.jsx'),
        'auth-ui': resolve(__dirname, 'frontend/authUi/main.jsx'),
        admin: resolve(__dirname, 'frontend/admin/main.jsx'),
        'reset-password': resolve(__dirname, 'frontend/passwordReset/main.jsx'),
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
