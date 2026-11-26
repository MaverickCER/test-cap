// A real sign-in journey through the built package (ADR 0023), run by run.mjs on Node, Bun and Deno and by worker.mjs
// on Cloudflare workerd: sign-up, email confirmation, a password and TOTP enrolment, sign-out, a refused and an accepted
// password sign-in, and the TOTP step-up, each request a Web `Request` through `test-cap/fetch` over the memory store.
// Plain JavaScript with no imports but dist/, so every runtime runs it as it is. argon2id runs at the test cost, so a
// slow runtime spends no time on hashing; the hasher itself is the one each runtime gets by default.

import { createAuth } from "../../dist/index.js"
import { fetchAuth } from "../../dist/fetch.js"
import { memoryStore } from "../../dist/store/memory.js"

const ORIGIN = "https://app.example"
const IDENTIFIER = "ada@example.com"
const PASSWORD = "correct horse battery staple"

/** Bytes of an unpadded RFC 4648 base32 string, as TOTP enrolment hands out its secret. */
function base32Decode(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  const bytes = []
  let buffer = 0
  let bits = 0
  for (const char of text) {
    buffer = (buffer << 5) | alphabet.indexOf(char)
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push((buffer >> bits) & 0xff)
    }
  }
  return Uint8Array.from(bytes)
}

/** The RFC 6238 code of `secret` at `ms`: HMAC-SHA-1, 30-second steps, 6 digits, on Web Crypto. */
async function totpCode(secret, ms) {
  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  )
  const counter = new DataView(new ArrayBuffer(8))
  counter.setBigUint64(0, BigInt(Math.floor(ms / 30_000)))
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter.buffer))
  const offset = mac[19] & 0x0f
  const value = new DataView(mac.buffer).getUint32(offset) & 0x7fffffff
  return String(value % 1_000_000).padStart(6, "0")
}

/**
 * Runs the journey and calls `check` with each condition it asserts. `fallback` says whether this runtime is one where
 * WebAssembly cannot compile, so argon2id must run on @noble/hashes and say so once through `onDiagnostic`.
 */
export async function journey(check, { fallback }) {
  let now = Date.UTC(2026, 10, 24)
  const outbox = []
  const diagnostics = []
  const auth = createAuth({
    store: memoryStore(),
    env: { APP_ENV: "test", APP_ORIGIN: ORIGIN, APP_SYSTEM_ID: "cross-runtime" },
    clock: { now: () => now },
    argon2Cost: { memoryKiB: 8, iterations: 1, parallelism: 1 },
    // An HIBP range answer with only a padding row: the password is not breached.
    hibpFetch: () =>
      Promise.resolve({
        ok: true,
        status: 200,
        text: () => Promise.resolve("0000000000000000000000000000000000A:0"),
      }),
    sendEmail: (message) => {
      outbox.push(message)
      return Promise.resolve()
    },
    onDiagnostic: (diagnostic) => diagnostics.push(diagnostic.code),
  })
  const handle = fetchAuth(auth, { clientAddress: () => "203.0.113.7" })

  // A browser: a cookie jar, the synchronizer token, and Origin on every POST.
  const cookies = new Map()
  let csrf = ""
  async function send(method, path, body) {
    const headers = new Headers()
    if (cookies.size > 0) {
      headers.set("cookie", [...cookies].map(([name, value]) => `${name}=${value}`).join("; "))
    }
    if (method === "POST") {
      headers.set("origin", ORIGIN)
      headers.set("content-type", "application/json")
      headers.set("x-csrf-token", csrf)
    }
    const response = await handle(
      new Request(`${ORIGIN}${path}`, {
        method,
        headers,
        body: method === "POST" ? JSON.stringify(body ?? {}) : undefined,
      }),
    )
    check(response !== null, `${path} is served`)
    for (const line of response.headers.getSetCookie()) {
      const [pair] = line.split(";")
      const equals = pair.indexOf("=")
      if (/;\s*Max-Age=0(?:;|$)/i.test(line)) cookies.delete(pair.slice(0, equals))
      else cookies.set(pair.slice(0, equals), pair.slice(equals + 1))
    }
    csrf = response.headers.get("x-csrf-token") ?? csrf
    const text = await response.text()
    return { status: response.status, json: text === "" ? undefined : JSON.parse(text) }
  }
  async function start() {
    const session = await send("GET", "/auth/session")
    csrf = session.json.csrfToken
    return session
  }
  /** Fails unless `reply` has `status` and, when given, the `outcome` the step expects. */
  function expect(step, reply, status, outcome) {
    check(
      reply.status === status && (outcome === undefined || reply.json?.outcome === outcome),
      `${step}: expected ${status}${outcome === undefined ? "" : ` ${outcome}`}, got ${reply.status} ${JSON.stringify(reply.json)}`,
    )
    return reply
  }

  // Sign-up: an account, the emailed code that confirms its address, a password, then TOTP, which completes AAL2.
  await start()
  expect("sign-up", await send("POST", "/auth/sign-up", { identifier: IDENTIFIER }), 200, "enroll")
  const code = /Your confirmation code is (\d{6})\./.exec(outbox.at(-1)?.text ?? "")?.[1]
  check(code !== undefined && outbox.at(-1).to === IDENTIFIER, "sign-up mails a confirmation code")
  expect("email confirmation", await send("POST", "/auth/email/confirm", { code }), 200, "enroll")
  expect("password", await send("POST", "/auth/password", { password: PASSWORD }), 200)
  const enrolment = expect("TOTP enrolment", await send("POST", "/auth/totp/enrol"), 200)
  const { authenticatorId, secret } = enrolment.json
  const confirmed = await send("POST", "/auth/totp/confirm", {
    authenticatorId,
    code: await totpCode(secret, now),
  })
  expect("TOTP confirmation", confirmed, 200, "allow")
  expect("sign-out", await send("POST", "/auth/sign-out"), 200)

  // Password sign-in: a wrong password is refused, the right one needs a step-up for the default requirement.
  await start()
  const wrong = await send("POST", "/auth/sign-in", {
    identifier: IDENTIFIER,
    password: `${PASSWORD}!`,
  })
  expect("sign-in with a wrong password", wrong, 401)
  const signedIn = await send("POST", "/auth/sign-in", {
    identifier: IDENTIFIER,
    password: PASSWORD,
  })
  expect("password sign-in", signedIn, 200, "step-up")

  // The step-up: a code from the step after enrolment's, which the replay check accepts.
  now += 30_000
  const verified = await send("POST", "/auth/totp/verify", { code: await totpCode(secret, now) })
  expect("TOTP step-up", verified, 200, "allow")
  const session = await send("GET", "/auth/session")
  check(typeof session.json.session?.subject === "string", "the stepped-up session is signed in")

  const fellBack = diagnostics.filter((each) => each === "argon2-fallback").length
  check(
    fellBack === (fallback ? 1 : 0),
    fallback
      ? `argon2id falls back to @noble/hashes and says so once, not ${fellBack} times`
      : "argon2id runs on hash-wasm, with no fallback",
  )
}
