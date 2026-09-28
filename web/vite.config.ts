import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During `npm run dev`, requests to /api and /healthz are proxied to the
// Go admin server so the dashboard can be developed with hot reload
// without needing a separate CORS setup -- in production the same Go
// binary serves both the built dashboard and the API from one origin.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:9000",
      "/healthz": "http://localhost:9000",
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
