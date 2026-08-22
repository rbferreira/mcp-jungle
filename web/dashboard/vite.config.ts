import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
      "@repo-assets": path.resolve(import.meta.dirname, "../../assets"),
    },
  },
  server: {
    port: 5173,
    fs: {
      allow: [path.resolve(import.meta.dirname, "../..")],
    },
    proxy: {
      "/api": "http://localhost:8080",
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
