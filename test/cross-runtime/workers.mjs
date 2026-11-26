// Runs the cross-runtime check in Cloudflare workerd (ADR 0023): serves worker.mjs with `wrangler dev`, requests it
// once, and exits 1 unless it answers that every check and the sign-in journey passed.
//
//   npm run build && node test/cross-runtime/workers.mjs
//
// wrangler is not a dependency of test-cap: it brings a platform binary and install scripts the dependency checks
// flag (ADR 0030). `npx` fetches the pinned version; set WRANGLER to another command, such as `wrangler`, to use one
// already installed. The worker runs with nodejs_compat, which test-cap needs on Workers (wrangler.toml says why).

import { spawn } from "node:child_process"
import { rmSync } from "node:fs"
import { createServer } from "node:net"
import path from "node:path"
import { fileURLToPath } from "node:url"

const WRANGLER = process.env.WRANGLER ?? "npx --yes wrangler@4.129.0"
const here = path.dirname(fileURLToPath(import.meta.url))
/** Where wrangler writes its bundle and local state, removed after the run. */
const state = path.join(here, ".wrangler")

/** A port the OS just handed out and released. */
function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.once("error", reject)
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address()
      server.close(() => resolve(port))
    })
  })
}

const port = await freePort()
const [command, ...args] = WRANGLER.split(" ")
const wrangler = spawn(
  command,
  [...args, "dev", "--config", path.join(here, "wrangler.toml"), "--ip", "127.0.0.1"].concat([
    "--port",
    String(port),
    "--log-level",
    "warn",
  ]),
  {
    env: { ...process.env, WRANGLER_SEND_METRICS: "false" },
    // Its own process group, so stopping it also stops the workerd process it starts.
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  },
)
let output = ""
wrangler.stdout.on("data", (chunk) => (output += chunk))
wrangler.stderr.on("data", (chunk) => (output += chunk))
const exited = new Promise((resolve) => wrangler.once("exit", resolve))

/** The worker's answer, once it is serving; null when wrangler exits or 180 tries a second apart go unanswered. */
async function answer() {
  for (let attempt = 0; attempt < 180; attempt += 1) {
    if (wrangler.exitCode !== null) return null
    const reply = await fetch(`http://127.0.0.1:${port}/`).catch(() => null)
    if (reply !== null) return { status: reply.status, text: await reply.text() }
    await new Promise((resolve) => setTimeout(resolve, 1_000))
  }
  return null
}

const reply = await answer()
try {
  process.kill(-wrangler.pid, "SIGTERM")
} catch {
  // Already gone.
}
await exited
rmSync(state, { recursive: true, force: true })
if (reply === null) {
  console.error(`cross-runtime: workerd: wrangler dev never answered\n${output}`)
  process.exit(1)
}
console.log(`cross-runtime: workerd (${WRANGLER}): ${reply.text}`)
if (reply.status !== 200) {
  console.error(output)
  process.exit(1)
}
