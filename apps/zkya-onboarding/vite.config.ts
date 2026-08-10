import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const root = fileURLToPath(new URL(".", import.meta.url));
const apiTarget = process.env.VITE_ZKYC_API_TARGET ?? "http://127.0.0.1:8787";
const proxy = {
  "/api": {
    target: apiTarget,
    changeOrigin: false,
    rewrite: (path: string) => path.replace(/^\/api/, ""),
  },
};

export default defineConfig({
  root,
  plugins: [react()],
  server: { host: "127.0.0.1", proxy },
  preview: { host: "127.0.0.1", proxy },
});
