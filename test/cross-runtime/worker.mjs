// The Cloudflare Workers side of the cross-runtime check (ADR 0023): workers.mjs serves this module with `wrangler dev`
// (workerd, compatibility date 2026-09-01, with nodejs_compat) and requests it once. It runs exercised.mjs's check for
// every value dist/index.js exports, then journey.mjs, where argon2id must fall back to @noble/hashes because workerd
// refuses to compile WebAssembly at run time. Everything runs inside the request: workerd refuses random values and
// timers at the top level of a module.

import * as dist from "../../dist/index.js"
import { CHECKS } from "./exercised.mjs"
import { journey } from "./journey.mjs"

/** Fails with a message naming the check. */
function check(condition, message) {
  if (!condition) throw new Error(`cross-runtime check failed: ${message}`)
}

export default {
  async fetch() {
    try {
      for (const name of Object.keys(CHECKS).sort()) await CHECKS[name](dist, check)
      await journey(check, { fallback: true })
      return new Response("all checks and the sign-in journey passed")
    } catch (error) {
      return new Response(error instanceof Error ? error.message : String(error), { status: 500 })
    }
  },
}
