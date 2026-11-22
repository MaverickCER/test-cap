import { defineConfig } from "tsup"

// The bundle ships UNMINIFIED. Never add any `minify*` option here: minified code is a Socket.dev
// supply-chain alert and the NoMinify check fails the contract on it. `dts: false` because
// declarations (with working declaration maps) are emitted by `tsc -p tsconfig.build.json` and
// shimmed into place by scripts/emit-dts-shims.mjs.
export default defineConfig({
  entry: {
    index: "src/index.ts",
    express: "src/adapters/express/index.ts",
    fetch: "src/adapters/fetch/index.ts",
    next: "src/adapters/next/index.ts",
    "tanstack-start": "src/adapters/tanstack-start/index.ts",
    "store/memory": "src/store/memory.ts",
  },
  format: ["esm", "cjs"],
  platform: "node",
  target: "node20",
  dts: false,
  sourcemap: true,
  treeshake: true,
})
