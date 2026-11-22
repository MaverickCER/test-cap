import { fileURLToPath } from "node:url"
import type { NextConfig } from "next"

const config: NextConfig = {
  // The example is its own npm project inside test-cap's repository; its root is this folder, not the repository's.
  turbopack: { root: fileURLToPath(new URL(".", import.meta.url)) },
}

export default config
