import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/oauth2": "http://127.0.0.1:8080",
      "/.well-known": "http://127.0.0.1:8080"
    }
  }
});
