import type { NextConfig } from "next";
import { fileURLToPath } from "node:url";

const apiBaseUrl = process.env.SIEMBIOT_API_BASE_URL ?? "http://127.0.0.1:8000";
const monorepoRoot = fileURLToPath(new URL("../..", import.meta.url));

const config: NextConfig = {
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${apiBaseUrl}/api/:path*` }];
  },
  poweredByHeader: false,
  turbopack: { root: monorepoRoot },
};

export default config;
