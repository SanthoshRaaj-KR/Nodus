import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Normally the console is served by the existing FastAPI app, not by a Node
// server: every byte of data already comes from /api/*, so a second runtime
// buys nothing. Vite builds into ui/static/app, which server.py already
// mounts, and `base` matches that mount point so the emitted asset URLs
// resolve.
//
// On Vercel (which sets VERCEL=1 during builds) the UI is instead deployed
// standalone, calling the API cross-origin via VITE_API_URL. It needs its
// output inside this project's root -- Vercel looks for `dist` there and
// finds nothing if the build writes to ../static/app, which is outside it.
//
// In dev, `npm run dev` proxies /api to the Python server so the React app and
// the real graph talk to each other without a build step in the loop.
const onVercel = !!process.env.VERCEL;

export default defineConfig({
  plugins: [react()],
  base: onVercel ? '/' : '/static/app/',
  build: {
    outDir: onVercel ? 'dist' : '../static/app',
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
