// Cross-runtime conformance (ADR 0023): runs the built dist/ under whichever runtime executes this file.
//
//   node test/cross-runtime/run.mjs
//   bun test/cross-runtime/run.mjs
//   deno run --allow-read test/cross-runtime/run.mjs
//
// Plain JavaScript with no imports but dist/ and no test framework, so every runtime runs it as it is. It checks the
// standard globals the core is built on, then every value dist/index.js exports. exercised.mjs names those exports;
// test/cross-runtime/coverage.test.ts fails when src/index.ts exports a value this file does not exercise, so the job
// grows with the package. Exits 1 on the first failed check.

import { EXERCISED } from "./exercised.mjs"

/** Fails with a message naming the runtime and the check. */
function check(condition, message) {
  if (!condition) throw new Error(`cross-runtime check failed: ${message}`)
}

async function globals() {
  check(typeof crypto?.getRandomValues === "function", "crypto.getRandomValues exists")
  check(
    crypto.getRandomValues(new Uint8Array(32)).length === 32,
    "crypto.getRandomValues fills a buffer",
  )
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode("abc")),
  )
  const hex = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")
  check(
    hex === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "SHA-256 matches FIPS 180-2",
  )
  const key = await crypto.subtle.importKey("raw", new Uint8Array(32), { name: "AES-GCM" }, false, [
    "encrypt",
  ])
  check(key.type === "secret", "AES-GCM keys import")
  const signer = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])
  const signature = await crypto.subtle.sign(
    { name: "Ed25519" },
    signer.privateKey,
    new Uint8Array(1),
  )
  check(
    await crypto.subtle.verify({ name: "Ed25519" }, signer.publicKey, signature, new Uint8Array(1)),
    "Ed25519 signs and verifies",
  )
  const headers = new Headers()
  headers.append("set-cookie", "a=1")
  headers.append("set-cookie", "b=2")
  check(headers.getSetCookie().length === 2, "Headers keeps each Set-Cookie separate")
  let fatal = false
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.of(0xc3, 0x28))
  } catch {
    fatal = true
  }
  check(fatal, "TextDecoder refuses malformed UTF-8")
  check(typeof structuredClone === "function", "structuredClone exists")
}

async function exports() {
  const dist = await import("../../dist/index.js")
  check(
    JSON.stringify(Object.keys(dist).sort()) === JSON.stringify([...EXERCISED].sort()),
    `dist exports exactly ${EXERCISED.join(", ")}`,
  )
  const transport = new dist.TransportError("body-too-large", "too big")
  check(
    transport instanceof Error && transport.name === "TransportError",
    "TransportError is an Error",
  )
  check(
    transport.code === "body-too-large" && transport.status === 413,
    "TransportError maps its code to 413",
  )
  check(
    new dist.TransportError("unsupported-media-type", "x").status === 415,
    "TransportError maps to 415",
  )
  check(new dist.TransportError("invalid-path", "x").status === 400, "TransportError maps to 400")
  const config = new dist.ConfigError(["first problem", "second problem"])
  check(config instanceof Error && config.name === "ConfigError", "ConfigError is an Error")
  check(
    config.problems.length === 2 && config.message.includes("- second problem"),
    "ConfigError lists every problem",
  )
}

// Read through globalThis: each runtime defines only its own global, and the others are undefined there.
const { Deno: deno, Bun: bun } = globalThis
const runtime =
  deno !== undefined
    ? `Deno ${deno.version.deno}`
    : bun !== undefined
      ? `Bun ${bun.version}`
      : `Node ${process.version}`

try {
  await globals()
  await exports()
  console.log(`cross-runtime: ${runtime}: all checks passed`)
} catch (error) {
  console.error(
    `cross-runtime: ${runtime}: ${error instanceof Error ? error.message : String(error)}`,
  )
  if (deno !== undefined) deno.exit(1)
  else process.exit(1)
}
