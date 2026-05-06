import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,                     // dev server port (different from prod 8090 to avoid collision)
    proxy: {
      "/session": "http://localhost:8090",
      "/tools": "http://localhost:8090",
      "/health": "http://localhost:8090",
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
