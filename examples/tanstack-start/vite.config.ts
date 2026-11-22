import { tanstackStart } from "@tanstack/react-start/plugin/vite"
import viteReact from "@vitejs/plugin-react"
import { defineConfig } from "vite"

export default defineConfig({
  plugins: [
    tanstackStart({
      // The generated route tree carries no blanket `eslint-disable` or `@ts-nocheck`: the root ESLint config ignores
      // the file, and `tsc` checks it like the rest of the app.
      router: { routeTreeFileHeader: [] },
    }),
    viteReact(),
  ],
})
