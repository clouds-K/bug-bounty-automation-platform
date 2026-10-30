import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // Reads frontend/.env (VITE_PROXY_TARGET) so no IP address is hard-coded in the repo.
  const env = loadEnv(mode, process.cwd(), '')

  return {
    plugins: [react()],
    server: {
      host: true, // listen on all interfaces (needed to reach the dev server from the host)
      proxy: {
        // Every /api/* request is forwarded server-side to Flask.
        // The browser only sees one origin, so httpOnly cookies are sent
        // without SameSite problems.
        '/api': {
          target: env.VITE_PROXY_TARGET || 'http://localhost:5001',
          changeOrigin: true,
        },
      },
    },
  }
})
