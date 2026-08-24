import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  root: path.resolve(__dirname, '.'),
  plugins: [react()],
  build: {
    outDir: path.resolve(__dirname, '../dist-web'),
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    strictPort: true,
  }
});
