import type { NextConfig } from "next";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const monorepoRoot = fileURLToPath(new URL("../..", import.meta.url));

/**
 * Keys this application may take from the repository-root `.env`.
 *
 * An allowlist rather than a merge: that file also holds database URLs and the
 * gateway secret, and none of them have any business being readable from the web
 * process. Copying the whole file in would put them one `process.env` away from
 * anything running here.
 */
const SHARED_KEYS: readonly string[] = [
  "SIEMBIOT_API_BASE_URL",
  "SIEMBIOT_DEV_IDENTITY_ISSUER",
  "SIEMBIOT_DEV_IDENTITY_SUBJECT",
  "SIEMBIOT_DEV_IDENTITY_EMAIL",
  "SIEMBIOT_DEV_IDENTITY_NAME",
];

/**
 * Next reads `.env` from the application directory, not from the root of a monorepo.
 * The local development identity lives in the root `.env`, beside the API's and the
 * worker's configuration, so without this the middleware sees nothing, injects no
 * headers, and every page in a real browser sits at 401 reporting that identity was
 * never received -- while an automated driver that sets those headers itself works
 * perfectly, which is a discrepancy nobody enjoys discovering.
 *
 * Development only. A deployment has a real gateway in front of it and configures
 * itself through its own environment.
 */
function loadRootEnvironment(): void {
  if (process.env.NODE_ENV !== "development") return;

  let contents: string;
  try {
    contents = readFileSync(new URL("../../.env", import.meta.url), "utf8");
  } catch {
    // A missing local .env is a normal state, not a failure: the values may already
    // be exported, and it must not stop the dev server from starting.
    return;
  }

  for (const line of contents.split(/\r?\n/)) {
    const match = /^\s*([A-Z0-9_]+)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    const [, key, rawValue] = match;
    if (!SHARED_KEYS.includes(key)) continue;
    // Never overwrite: anything explicitly exported into this process was chosen
    // deliberately and outranks a file.
    if (process.env[key] !== undefined) continue;
    const value = rawValue.trim().replace(/^(['"])(.*)\1$/, "$2");
    if (value) process.env[key] = value;
  }
}

loadRootEnvironment();

const apiBaseUrl = process.env.SIEMBIOT_API_BASE_URL ?? "http://127.0.0.1:8000";

const config: NextConfig = {
  // Emits a server bundle with only the dependencies it actually reaches, so the
  // production image carries no build toolchain. A development toolchain shipped to
  // production is a toolchain available to whoever gets in.
  output: "standalone",
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${apiBaseUrl}/api/:path*` }];
  },
  poweredByHeader: false,
  turbopack: { root: monorepoRoot },
};

export default config;
