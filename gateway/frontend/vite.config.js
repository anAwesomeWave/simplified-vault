import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

const target = process.env.API_TARGET || 'http://localhost';

export default defineConfig({
  plugins: [svelte()],
  server: {
    proxy: {
      '/auth': { target },
      '/secrets': {
        target,
        // Browser links open the app; fetch requests still reach the API.
        bypass(req) {
          if (req.method === 'GET' && req.headers.accept?.includes('text/html')) {
            return '/index.html';
          }
        },
      },
    },
  },
});
