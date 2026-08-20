import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The console is served by the existing FastAPI app, not by a Node server:
// every byte of data already comes from /api/*, so a second runtime would buy
// nothing. Vite builds into ui/static/app, which server.py already mounts, and
// `base` matches that mount point so the emitted asset URLs resolve.
//
// In dev, `npm run dev` proxies /api to the Python server so the React app and
// the real graph talk to each other without a build step in the loop.
export default defineConfig({
  plugins: [react()],
  base: '/static/app/',
  build: {
    outDir: '../static/app',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
});
