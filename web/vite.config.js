// vite.config.js
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Front accessible sur http://localhost:5173
// Plus de proxy car les appels API passent par VITE_API_URL dans api.js
export default defineConfig({
  plugins: [react()],
  server: {
    host: "localhost",
    port: 5173,
  },
  resolve: { alias: { "@": "/src" } },
});
