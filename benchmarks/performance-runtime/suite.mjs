// test-cap runtime benchmark suite. WRITING-BENCHMARKS.md explains what to measure and how to document it;
// `defineSuite` refuses a suite whose documentation is missing or a placeholder.
//
// `npm run benchmark` runs the full ladder: it writes to .benchmark-local/performance-runtime/ on a developer machine and
// to this folder in CI. Add `--quick` for a smoke test whose output is never committed. `npm run benchmark:check`
// validates the documentation only and measures nothing.
//
// Everything goes through the built entry points a consumer imports: `test-cap`, the four adapters
// (`test-cap/express`, `test-cap/fetch`, `test-cap/next`, `test-cap/tanstack-start`) and `test-cap/store/memory`. The
// transport parsers, CSRF, the session reads and argon2id are internal, so they are measured through `auth.handle`,
// which is how every request reaches them. Inputs are built from the index, never from Math.random or the clock, so
// two runs measure the same work.

import { IncomingMessage, ServerResponse } from "node:http"
import { Duplex } from "node:stream"
import { defineSuite } from "internal-package-contract/benchmark"
import { createAuth, createStoreLimiter, defineAuthPolicy } from "../../dist/index.js"
import { expressAuth } from "../../dist/express.js"
import { fetchAuth, withAuth } from "../../dist/fetch.js"
import { nextAuthHandler, nextProxy, nextServerAuth } from "../../dist/next.js"
import { tanstackStartAuth, tanstackStartMiddleware } from "../../dist/tanstack-start.js"
import { memoryStore } from "../../dist/store/memory.js"

const ORIGIN = "https://app.example"

/** A deterministic 32-byte key, base64url, for key-ring entry `index`. */
function keyBytes(index) {
  return Buffer.from(
    Uint8Array.from({ length: 32 }, (_, i) => (i * 31 + index * 7 + 1) % 256),
  ).toString("base64url")
}

/** A key ring of `count` entries, newest first, as `AUTH_*_KEY` holds it. */
function keyRing(prefix, count) {
  return Array.from(
    { length: count },
    (_, index) => `${prefix}${String(index)}:${keyBytes(index)}`,
  ).join(",")
}

/** The environment of a test-mode deployment with `ringSize` entries in each key ring. */
function env(ringSize = 1) {
  return {
    APP_ENV: "test",
    APP_ORIGIN: ORIGIN,
    APP_SYSTEM_ID: "benchmark",
    AUTH_ENCRYPTION_KEY: keyRing("e", ringSize),
    AUTH_CSRF_KEY: keyRing("c", ringSize),
  }
}

/** HIBP's range answer with only a padding row: no password is breached, and nothing touches the network. */
const hibpClear = () =>
  Promise.resolve({
    ok: true,
    status: 200,
    text: () => Promise.resolve("0000000000000000000000000000000000A:0\r\n"),
  })

/** The reduced argon2id cost test mode accepts (the same one test-cap's own tests use); the default is m=19456, t=2, p=1. */
const TEST_COST = { memoryKiB: 8, iterations: 1, parallelism: 1 }

/**
 * The argon2id cost createAuth runs with. `test` is the reduced test-mode cost (the `argon2Cost` option), so a ladder
 * of thousands of samples finishes; `real` is the production cost ADR 0010 fixes.
 */
function auth(cost = "test", ringSize = 1, extra = {}) {
  return createAuth({
    store: memoryStore(),
    env: env(ringSize),
    hibpFetch: hibpClear,
    sendEmail: keepEmail([]),
    throttle: UNBLOCKED,
    rateLimit: UNLIMITED_REQUESTS,
    emailLimit: UNLIMITED_MAIL,
    ...(cost === "test" ? { argon2Cost: TEST_COST } : {}),
    ...extra,
  })
}

/**
 * A benchmark repeats one failing sign-in thousands of times. With the default throttle the sixth would be refused
 * with 429 before any hash runs, and the figure would be the refusal's. Raising the free attempts past any sample count
 * keeps every request on the full path: the throttle still reads its blocks and counts each attempt, it never blocks.
 */
const UNBLOCKED = { freeFailures: Number.MAX_SAFE_INTEGER }

/**
 * A benchmark sends thousands of requests from one client in seconds; the default request limits would answer 429
 * after 10 or 100. Raising every limit past any sample count keeps each request on its full path: the limiter still
 * counts every request in the store, it never refuses one.
 */
const UNLIMITED_REQUESTS = {
  max: Number.MAX_SAFE_INTEGER,
  rules: Object.fromEntries(
    [
      "sign-in",
      "step-up",
      "totp/verify",
      "totp/enrol",
      "totp/confirm",
      "email/confirm",
      "recovery",
      "sign-up",
    ].map((id) => [id, { windowMs: 10_000, max: Number.MAX_SAFE_INTEGER }]),
  ),
}

/** The same for confirmation mail: every send is counted against both limits, and none is held back. */
const UNLIMITED_MAIL = {
  perAddress: [{ windowMs: 60_000, max: Number.MAX_SAFE_INTEGER }],
  perClient: { windowMs: 3_600_000, max: Number.MAX_SAFE_INTEGER },
}

/** A mail sender that keeps every message in `outbox`, so a benchmark can read a confirmation code back. */
function keepEmail(outbox) {
  return (message) => {
    outbox.push(message)
    return Promise.resolve()
  }
}

/** A clock the benchmark moves by hand (test mode only), so each TOTP code falls in a new time step. */
function handClock(start = 1_700_000_000_000) {
  let now = start
  return { now: () => now, advance: (ms) => (now += ms) }
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

/** RFC 6238 TOTP (SHA-1, 6 digits, 30-second step) for a base32 secret at `epochMs`, with Web Crypto. */
async function totp(secret, epochMs) {
  let bits = ""
  for (const char of secret.replace(/=+$/, ""))
    bits += BASE32.indexOf(char).toString(2).padStart(5, "0")
  const key = Uint8Array.from(bits.match(/.{8}/g) ?? [], (byte) => Number.parseInt(byte, 2))
  const counter = new Uint8Array(8)
  new DataView(counter.buffer).setBigUint64(0, BigInt(Math.floor(epochMs / 30_000)))
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  )
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, counter))
  const offset = (mac[19] ?? 0) & 0x0f
  const value = new DataView(mac.buffer).getUint32(offset) & 0x7fffffff
  return String(value % 1_000_000).padStart(6, "0")
}

/** A browser for one Auth: keeps its cookies and the newest CSRF token, as a real one does across requests. */
class Browser {
  constructor(instance) {
    this.instance = instance
    this.cookies = new Map()
    this.csrf = ""
  }
  async send(method, path, fields) {
    const headers = {
      Origin: ORIGIN,
      Cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "),
    }
    if (fields !== undefined) {
      // JSON, as the browser client sends: a form post that completes a step answers with a 303 to the next page.
      headers["Content-Type"] = "application/json"
      headers["X-CSRF-Token"] = this.csrf
    }
    const reply = await this.instance.handle(
      request(method, path, headers, fields === undefined ? null : JSON.stringify(fields)),
    )
    for (const line of reply.headers.getSetCookie()) {
      const [pair] = line.split(";")
      const at = pair.indexOf("=")
      const value = pair.slice(at + 1)
      if (value === "") this.cookies.delete(pair.slice(0, at))
      else this.cookies.set(pair.slice(0, at), value)
    }
    const issued = reply.headers.get("x-csrf-token")
    if (issued !== null) this.csrf = issued
    const text = reply.body === null ? "" : new TextDecoder().decode(reply.body)
    const json = text.startsWith("{") ? JSON.parse(text) : undefined
    if (json?.csrfToken !== undefined) this.csrf = json.csrfToken
    return { status: reply.status, json }
  }
}

/** Fails setup loudly when a step of the flow does not answer 2xx, so no benchmark measures an error by accident. */
function ok(reply, step) {
  if (reply.status < 200 || reply.status > 299)
    throw new Error(`${step} answered ${String(reply.status)}`)
  return reply
}

/**
 * An enrolled account with `authenticators` TOTP authenticators, signed in at AAL2 in `browser`: sign-up, email
 * confirmation (the code read back from the outbox), password, then each authenticator enrolled and confirmed.
 */
async function enrolled(authenticators) {
  const clock = handClock()
  const outbox = []
  const instance = auth("test", 1, { clock, sendEmail: keepEmail(outbox) })
  const browser = new Browser(instance)
  ok(await browser.send("GET", "/auth/session"), "session")
  ok(await browser.send("POST", "/auth/sign-up", { identifier: "ada@example.com" }), "sign-up")
  const code = /\b(\d{6})\b/.exec(outbox.at(-1)?.text ?? "")?.[1] ?? ""
  ok(await browser.send("POST", "/auth/email/confirm", { code }), "email confirm")
  ok(
    await browser.send("POST", "/auth/password", { password: "correct horse battery staple" }),
    "password",
  )
  const secrets = []
  for (let i = 0; i < authenticators; i += 1) {
    const begun = ok(await browser.send("POST", "/auth/totp/enrol", {}), "totp enrol").json
    ok(
      await browser.send("POST", "/auth/totp/confirm", {
        authenticatorId: begun.authenticatorId,
        code: await totp(begun.secret, clock.now()),
      }),
      "totp confirm",
    )
    secrets.push(begun.secret)
  }
  return { instance, browser, clock, secrets }
}

/** A request as `auth.handle` takes it. */
function request(method, path, headers = {}, body = null) {
  return {
    method,
    url: `${ORIGIN}${path}`,
    headers: new Headers(headers),
    body: body === null ? null : new TextEncoder().encode(body),
  }
}

/** A browser's first visit: the pre-session cookie and the CSRF token bound to it, for a following POST. */
async function browser(instance) {
  const reply = await instance.handle(request("GET", "/auth/session"))
  const cookie = reply.headers
    .getSetCookie()
    .map((line) => line.split(";")[0])
    .join("; ")
  const { csrfToken } = JSON.parse(new TextDecoder().decode(reply.body))
  return { cookie, csrfToken }
}

/** A form POST from that browser. */
async function post(instance, path, fields, session) {
  return instance.handle(
    request(
      "POST",
      path,
      {
        Origin: ORIGIN,
        Cookie: session.cookie,
        "X-CSRF-Token": session.csrfToken,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      new URLSearchParams(fields).toString(),
    ),
  )
}

/**
 * A valid address exactly `length` characters long (16 to 254): the local part "ada" and a domain of labels of at most
 * 60 characters ending in "com", because the local part may not exceed 64 characters and a label 63.
 */
function identifier(length) {
  const labels = []
  // What the labels and their dots must fill: the whole length less "ada@" and the final "com".
  let remaining = length - "ada@".length - "com".length
  while (remaining > 0) {
    // Each label takes its characters plus one dot; never leave exactly one character, which cannot be a label.
    let size = Math.min(60, remaining - 1)
    if (remaining - (size + 1) === 1) size -= 1
    labels.push("x".repeat(size))
    remaining -= size + 1
  }
  return `ada@${labels.map((label) => `${label}.`).join("")}com`
}

// The adapter benchmarks. Each builds the handler or middleware an adapter returns in setup, untimed, and sends it n GET
// requests one after another, so n is the suite's own unit and the per-request overhead is the run's time divided by n.

/** The public list every adapter benchmark passes: one exact entry, the home page. */
const PUBLIC = ["/"]

/** The path each route variant requests. */
const PATH = { auth: "/auth/session", public: "/", protected: "/account" }

/** What a request the adapter hands on to the app counts as in a run's total. */
const PASSED = 200

/** The status each route variant answers with no session: the session request, the app, and deny by default's 401. */
const ANSWER = { auth: 200, public: PASSED, protected: 401 }

/** The three requests every deny-by-default adapter sees, as variants. */
const ROUTE_VARIANTS = [
  {
    name: "auth-route",
    description:
      "GET /auth/session, the request every page load makes first: served by auth.handle, and the reply converted back.",
    options: { route: "auth" },
  },
  {
    name: "public-route",
    description:
      "GET /, on the public list: the path match hands it to the app without reading a session.",
    options: { route: "public" },
  },
  {
    name: "protected-route",
    description:
      "GET /account with no session: deny by default refuses it with a 401 the adapter converts back.",
    options: { route: "protected" },
  },
]

/** The tier axis of every adapter benchmark. */
const REQUESTS = {
  name: "requests",
  how: "swept",
  description: "The tier axis: requests sent through the returned handler, one after another.",
}

/** No adapter benchmark carries a session cookie. */
const NO_SESSION = {
  name: "session",
  how: "fixed",
  value: "none",
  description: "No request carries a session cookie, so no request reads a session from the store.",
}

const SIGNED_IN = {
  name: "a signed-in request",
  reason:
    "A live session adds auth.require's store read and assurance check, which auth-require measures; the adapter's own work, the conversion and the path match, does not change.",
}

const CONCURRENT = {
  name: "concurrent requests",
  reason:
    "The returned handler keeps no state between requests, so requests in parallel would measure the event loop, not the adapter.",
}

const REQUEST_BODY = {
  name: "a request body",
  reason:
    "Every request here is a GET. A body under /auth/ is read once, capped at the core's 64 KiB limit, and sign-up-body measures a body through auth.handle.",
}

const ADAPTER_IN_END_TO_END = {
  callsPerOperation: 0,
  description: "Adapter cost, outside the core request measured end to end.",
}

/**
 * How an adapter benchmark accounts for its `auth` argument: one test-mode Auth from createAuth over the suite's
 * memory store. `calls` names the members the adapter's handler or helpers call; they never reach the others.
 */
function authFixed(calls) {
  const same = "fixed: one test-mode Auth from createAuth over the suite's memory store"
  return Object.fromEntries(
    ["admin", "handle", "require", "session"].map((member) => [
      `auth.${member}`,
      calls.includes(member)
        ? `${same}, called on every request that reaches it`
        : `${same}; nothing it returns calls auth.${member}`,
    ]),
  )
}

/** Fails setup loudly when a request does not answer as its variant should, so no benchmark measures the wrong path. */
function expectStatus(status, wanted, step) {
  if (status !== wanted)
    throw new Error(`${step} answered ${String(status)}, not ${String(wanted)}`)
}

/** Sends every request through `send` one after another and sums the statuses, a value that depends on the work. */
async function sequentially(requests, send) {
  let total = 0
  for (const req of requests) total += await send(req)
  return total
}

/** The status a fetch-style handler answered, or PASSED when it handed the request on (`null` or `undefined`). */
const statusOf = (reply) => reply?.status ?? PASSED

/** `count` Web Requests for `path`, built ahead, so the runtime's own parsing stays out of the figure. */
function webRequests(count, path, headers = {}) {
  return Array.from({ length: count }, () => new Request(`${ORIGIN}${path}`, { headers }))
}

/** The empty response the app behind `withAuth` answers, built once, so the figure is the adapter's and not the app's. */
const APP_RESPONSE = new Response(null, { status: 200 })

/** A constant client address, read from memory as Deno's `info.remoteAddr.hostname` is. */
const clientAddress = () => "198.51.100.1"

/**
 * One request as Node's HTTP server hands it to Express: a real IncomingMessage and ServerResponse over a socket that
 * discards what it is written. Node still serializes the status line and every header, so writing the reply is in the
 * figure; only the kernel's send is left out.
 */
function nodeExchange(path) {
  const socket = new Duplex({
    read() {},
    write(_chunk, _encoding, done) {
      done()
    },
  })
  socket.remoteAddress = "198.51.100.1"
  const req = new IncomingMessage(socket)
  req.method = "GET"
  req.url = path
  req.rawHeaders = ["Host", "app.example"]
  // A GET has no body: Node's parser marks the message complete and ends the stream at once. Without `complete`, Node
  // would destroy the socket once the adapter reads the stream to its end, and the reply would never be written.
  req.complete = true
  req.push(null)
  const res = new ServerResponse(req)
  res.assignSocket(socket)
  return { req, res }
}

/** One exchange through the middleware: PASSED when it calls `next`, else the status it wrote once Node finished. */
function throughExpress(middleware, { req, res }) {
  return new Promise((resolve, reject) => {
    res.once("finish", () => resolve(res.statusCode))
    middleware(req, res, (error) => (error === undefined ? resolve(PASSED) : reject(error)))
  })
}

/** The request headers `next/headers` resolves for the server helpers: three lines, none of them a session cookie. */
const NEXT_HEADERS = [
  ["host", "app.example"],
  ["accept", "text/html"],
  ["user-agent", "benchmark"],
]

/** A session cookie of a valid shape; the proxy only checks that one is present and never reads the store. */
const SESSION_COOKIE = `__Host-test-cap=${"s".repeat(43)}`

const STORE_FIXED = {
  "config.store": "fixed: the memory store, so the figure is test-cap's own work and no database's",
  "config.env": "fixed: a test-mode environment with one entry per key ring",
  "config.hibpFetch":
    "fixed: answers from memory with a padding row, so no request leaves the process",
  "config.policy": "fixed: absent, so every requirement is the default AAL2",
  "config.tenant": "fixed: absent, the default tenant",
  "config.clock": "fixed: absent, the system clock",
  "config.random": "fixed: absent, the system random source",
  "config.sendEmail": "fixed: keeps each message in memory; sending is the app's own cost",
  "config.onEvent": "fixed: absent; a sink is the app's own cost and cannot change an outcome",
  "config.trustedProxies":
    "fixed: absent, so the socket address is the client and no forwarded header is read",
  "config.throttle":
    "fixed: absent, the defaults; checking them is the same few comparisons for any value",
  "config.stuffing":
    "fixed: absent, the defaults; checking them is the same few comparisons for any value",
  "config.challengeHook": "fixed: absent; createAuth only stores it",
  "config.forwardedHeader": "fixed: absent; with no trusted proxy it is never read",
  "config.publicBasePath":
    "fixed: absent; a prefix is one fixed-length check at startup and one string join per link",
  "config.onDiagnostic":
    "fixed: absent; a sink is the app's own cost and runs at most once per code",
  "config.argon2Cost":
    "fixed: the reduced test-mode cost; the sign-in benchmark's variant measures the real one",
  "config.rateLimit":
    "fixed: every limit raised past any sample count, so each request is counted once in the store and none is refused; store-limiter measures that count",
  "config.emailLimit":
    "fixed: both mail limits raised past any sample count, so each send is counted and none is held back",
  "config.failureCeiling":
    "fixed: absent, the default 100; the check is one comparison per failure",
  "config.emailCodeAttempts":
    "fixed: absent, the default 5; the check is one comparison per attempt",
  "config.refusalEvents":
    "fixed: absent, the default first; it runs only for a refused request, which no benchmark sends",
  "config.argon2Hasher":
    "fixed: absent, the built-in hasher; an app's own hasher costs what it costs, and test-cap adds one format check per hash",
  "config.requireClientAddress":
    "fixed: absent; it is read only for a request with no client address, and every benchmark request has one",
}

/** How the Next.js and TanStack Start handlers' `options` are accounted for. */
const NO_CLIENT_ADDRESS = {
  options:
    "fixed: absent, so the core sees no client address and counts no request limit; with one, each request adds the one counter increment fetch-handler measures",
}

export default defineSuite({
  package: {
    name: "test-cap",
    bundleFiles: [
      "dist/index.js",
      "dist/express.js",
      "dist/fetch.js",
      "dist/next.js",
      "dist/tanstack-start.js",
      "dist/store/memory.js",
    ],
  },

  workload: {
    unit: "request",
    description:
      "One HTTP request an app hands to test-cap. Each function names what its n counts instead (cookies on a request, key-ring entries, policy requirements, public paths, stored records, password characters), because the cost of an authentication request grows with those, not with a batch size. 640 is a busy minute of sign-in traffic for one of the owner's apps.",
    typicalN: 640,
  },

  endToEnd: {
    purpose:
      "What an app pays per request for routing it through test-cap instead of answering it itself: n requests for the session and a CSRF token, the request every page load makes first.",
    baseline: {
      description:
        "n calls of an async function that returns a fixed response, with no package involved.",
      setup: (n) => n,
      run: async (n) => {
        let total = 0
        for (let i = 0; i < n; i += 1) total += (await Promise.resolve({ status: 200 })).status
        return total
      },
    },
    withPackage: {
      description:
        "n GET /auth/session requests through auth.handle: path check, cookie parse, session read, CSRF token, security headers.",
      setup: (n) => ({ instance: auth(), n }),
      run: async ({ instance, n }) => {
        let total = 0
        for (let i = 0; i < n; i += 1)
          total += (await instance.handle(request("GET", "/auth/session"))).status
        return total
      },
    },
    variables: [
      { name: "requests", how: "swept", description: "The tier axis: requests per operation." },
      {
        name: "session",
        how: "fixed",
        value: "none",
        description:
          "Each request carries no cookie, so the store lookup misses: the first visit every browser makes.",
      },
      {
        name: "runtime",
        how: "fixed",
        value: "node",
        description:
          "Measured on Node only; Bun and Deno are covered for correctness by the cross-runtime job, not timed.",
      },
    ],
  },

  notBenchmarked: {
    platform:
      "Builds a platform preset object once, when the app calls createAuth; its cost is a few property reads at startup and nothing per request.",
  },

  functions: [
    {
      id: "session-cookies",
      name: "auth.handle (GET /auth/session)",
      why: "Every page load asks for the session and a CSRF token first, so the cookie parser and the session read run on every request a browser makes. A browser sends every cookie the app's domain holds, often dozens.",
      poorPerformanceMeans:
        "A parser that grew faster than the cookie header would let a client with many cookies slow every request, and an attacker could send a large Cookie header to burn server time.",
      expectedComplexity: "linear",
      complexityReason:
        "The Cookie header is split once and each pair is checked once for the session and pre-session names, so the work grows with the number of cookies.",
      variables: [
        {
          name: "cookies",
          how: "swept",
          description: "Cookies in the request's Cookie header, none of them test-cap's.",
        },
        {
          name: "session",
          how: "fixed",
          value: "none",
          description: "No session cookie, the first-visit path.",
        },
      ],
      notCovered: [
        {
          name: "a live session",
          reason:
            "Reading a stored session is one memory-store get; the store benchmarks below measure it with n records.",
        },
      ],
      covers: {},
      inEndToEnd: { callsPerOperation: 1, description: "One per request in the end-to-end run." },
      setup: (n) => ({
        instance: auth(),
        cookie: Array.from({ length: n }, (_, i) => `app${String(i)}=value${String(i)}`).join("; "),
      }),
      run: async ({ instance, cookie }) =>
        (await instance.handle(request("GET", "/auth/session", { Cookie: cookie }))).status,
    },
    {
      id: "sign-up-body",
      name: "auth.handle (POST /auth/sign-up)",
      why: "Sign-up is the first state-changing request: it runs the origin check, the form parser, the CSRF verification and the identifier rules before any account exists, so it is the path an unauthenticated client can reach most cheaply.",
      poorPerformanceMeans:
        "Cost that grows faster than the body would let anonymous clients exhaust the server with large sign-up bodies before rate limiting (phase 4) applies.",
      expectedComplexity: "constant",
      complexityReason:
        "The body is parsed in one pass, but at these sizes that pass is dwarfed by fixed work every sign-up does: the CSRF MAC check, creating the account and the session, and issuing a token.",
      tiers: [16, 32, 64, 128, 254],
      tiersReason:
        "An identifier longer than 254 characters is refused before any account is created, a different and cheaper path, so the ladder stops at the longest valid address.",
      variables: [
        {
          name: "identifier characters",
          how: "swept",
          description: "Length of the submitted identifier, every size a valid address.",
        },
        {
          name: "body format",
          how: "fixed",
          value: "form",
          description: "URL-encoded, which is what the default pages post.",
        },
      ],
      notCovered: [
        {
          name: "JSON bodies",
          reason:
            "The JSON parser is the other branch of the same body reader; the form branch is what the default pages use.",
        },
      ],
      covers: {},
      inEndToEnd: {
        callsPerOperation: 0,
        description: "Not part of the end-to-end request; measured on its own.",
      },
      fresh: true,
      setup: async (n) => {
        const instance = auth()
        return { instance, session: await browser(instance), fields: { identifier: identifier(n) } }
      },
      run: async ({ instance, session, fields }) =>
        (await post(instance, "/auth/sign-up", fields, session)).status,
    },
    {
      id: "sign-in-argon2",
      name: "auth.handle (POST /auth/sign-in)",
      why: "Every password sign-in runs argon2id, and so does every failed one, an unknown account included, so that a reply's timing never says whether an account exists. It is the most expensive thing test-cap does per request.",
      poorPerformanceMeans:
        "Sign-in latency users feel directly, and server capacity: argon2id holds memory for each hash, so slow hashing under load queues sign-ins behind the concurrency limit and answers 503 busy.",
      expectedComplexity: "constant",
      complexityReason:
        "argon2id's cost is fixed by its memory and iteration parameters; the password is hashed once into its fixed-size input, so its length barely changes the work.",
      tiers: [8, 16, 32, 64, 128, 256],
      tiersReason:
        "Passwords are capped at 256 characters (ADR 0010), so longer inputs are refused before hashing and would measure the refusal, not argon2id.",
      variables: [
        {
          name: "password characters",
          how: "swept",
          description: "Length of the submitted password.",
        },
        {
          name: "hash cost",
          how: "variant",
          description:
            "The test-mode cost the ladder runs at, and the real production cost, measured as the variants below.",
        },
        {
          name: "account",
          how: "fixed",
          value: "unknown",
          description:
            "No account has the identifier, so the dummy hash runs: the same work a known account's check does.",
        },
      ],
      variants: [
        {
          name: "test-cost",
          description: "The reduced test-mode argon2id cost (argon2Cost: m=8 KiB, t=1, p=1).",
          options: { cost: "test" },
        },
        {
          name: "real-cost",
          description: "The production argon2id cost ADR 0018 fixes: m=19456 KiB, t=2, p=1.",
          options: { cost: "real" },
        },
      ],
      notCovered: [
        {
          name: "concurrent sign-ins",
          reason:
            "The concurrency limit makes simultaneous hashes queue; measuring the queue would measure the limit, which ADR 0010 sets, not the hash.",
        },
      ],
      covers: {},
      inEndToEnd: {
        callsPerOperation: 0,
        variant: "test-cost",
        description: "Not part of the end-to-end request; measured on its own.",
      },
      setup: async (n, options) => {
        const instance = auth(options?.cost ?? "test")
        return {
          instance,
          session: await browser(instance),
          fields: { identifier: "nobody@example.com", password: "p".repeat(n) },
        }
      },
      run: async ({ instance, session, fields }) =>
        (await post(instance, "/auth/sign-in", fields, session)).status,
    },
    {
      id: "create-auth",
      name: "createAuth",
      why: "Runs once per process start, and every serverless cold start pays it: it checks the deployment, parses every key ring and wires the store, policy and methods.",
      poorPerformanceMeans:
        "Slower cold starts on every deploy and every scale-up from zero; a key-ring parser that grew faster than the ring would make key rotation, which adds entries, slow startup down.",
      expectedComplexity: "linear",
      complexityReason: "Each key-ring entry is split and base64url-decoded once.",
      variables: [
        {
          name: "key-ring entries",
          how: "swept",
          description: "Entries in each of AUTH_ENCRYPTION_KEY and AUTH_CSRF_KEY.",
        },
      ],
      notCovered: [
        {
          name: "refusal",
          reason:
            "A deployment that may not start throws once at startup; its cost is not paid by a running app.",
        },
      ],
      covers: { createAuth: { ...STORE_FIXED, "config.env": "swept" } },
      inEndToEnd: {
        callsPerOperation: 0,
        description: "Runs once at startup, outside the per-request path.",
      },
      setup: (n) => ({ store: memoryStore(), env: env(n) }),
      run: ({ store, env: environment }) =>
        typeof createAuth({
          store,
          env: environment,
          hibpFetch: hibpClear,
          sendEmail: keepEmail([]),
          argon2Cost: TEST_COST,
        }).handle,
    },
    {
      id: "define-auth-policy",
      name: "defineAuthPolicy",
      why: "Runs once at startup over every requirement id the app (or access-cap) maps; a large app may define hundreds.",
      poorPerformanceMeans: "Slower cold starts for apps with many requirements.",
      expectedComplexity: "linear",
      complexityReason: "Each requirement is validated once and stored in a map.",
      variables: [
        { name: "requirements", how: "swept", description: "Requirement ids in the policy." },
      ],
      notCovered: [
        {
          name: "trust configuration",
          reason: "OIDC issuer trust arrives in phase 5; phase 3 has no issuer to configure.",
        },
      ],
      covers: {
        defineAuthPolicy: {
          "input.requirements": "swept",
          "input.version": "fixed: one short label, which is only stored",
          "input.defaultRequirement": "fixed: absent, the AAL2 default",
          "input.emailSignIn": "fixed: absent, off, the default",
          "input.timeouts": "fixed: absent, the defaults",
          "input.trust": "not covered: OIDC trust arrives in phase 5",
        },
      },
      inEndToEnd: {
        callsPerOperation: 0,
        description: "Runs once at startup, outside the per-request path.",
      },
      setup: (n) =>
        Object.fromEntries(
          Array.from({ length: n }, (_, i) => [
            `area${String(i)}.update`,
            { level: "AAL2", multiFactorWithinMs: 300_000 },
          ]),
        ),
      run: (requirements) => defineAuthPolicy({ version: "benchmark", requirements }).version,
    },
    {
      id: "express-public-paths",
      name: "expressAuth",
      why: "The middleware sits in front of every route of an Express app; each request outside /auth/ is matched against the public list before the app sees it.",
      poorPerformanceMeans:
        "Every request to the app pays the matching cost; an app with a long public list would slow down all of its traffic, not only sign-in.",
      expectedComplexity: "linear",
      complexityReason:
        "Exact entries are a set lookup, but each wildcard entry is a prefix test, and a path that matches the last one is tested against all of them.",
      variables: [
        {
          name: "public wildcard entries",
          how: "swept",
          description: "Entries such as /docs0/* in the public list; the request matches the last.",
        },
      ],
      notCovered: [
        {
          name: "protected routes",
          reason: "A protected route adds the session read, which the session benchmark measures.",
        },
      ],
      covers: {
        expressAuth: {
          ...authFixed(["handle"]),
          options: "swept",
        },
      },
      inEndToEnd: {
        callsPerOperation: 0,
        description: "Adapter cost, outside the core request measured end to end.",
      },
      setup: (n) => ({
        middleware: expressAuth(auth(), {
          public: Array.from({ length: n }, (_, i) => `/docs${String(i)}/*`),
        }),
        url: `/docs${String(n - 1)}/page`,
      }),
      run: ({ middleware, url }) =>
        new Promise((resolve, reject) => {
          const req = {
            method: "GET",
            url,
            rawHeaders: ["Host", "app.example"],
            socket: { remoteAddress: "127.0.0.1" },
            readableEnded: false,
            on: () => undefined,
            pause: () => undefined,
          }
          const res = {
            statusCode: 200,
            writableFinished: false,
            setHeader: () => undefined,
            end: reject,
            once: () => undefined,
          }
          middleware(req, res, (error) =>
            error === undefined ? resolve(req.auth === null) : reject(error),
          )
        }),
    },
    {
      id: "express-requests",
      name: "expressAuth (per request)",
      why: "The middleware sits in front of every route of an Express app, so every request pays it: the raw header lines turned into Headers, the path match, and under /auth/ the raw body read and the reply written to Node's response. Each request is a real Node IncomingMessage and ServerResponse over a socket that discards its writes, so Node's own header serialization is in the figure and the network is not.",
      poorPerformanceMeans:
        "A tax on all of the app's traffic, public pages included: slower responses and more servers for the same load. Cost that grew with the number of requests served would mean the middleware keeps something per request, and a long-running process would slow down until it restarts.",
      expectedComplexity: "linear",
      complexityReason:
        "Each request does the same fixed work: one header conversion, one path match and at most one call into the core, so n requests cost n times one.",
      variables: [
        REQUESTS,
        {
          name: "route",
          how: "variant",
          description:
            "The session request, a public page and a protected page, as the variants below.",
        },
        NO_SESSION,
      ],
      variants: ROUTE_VARIANTS,
      notCovered: [SIGNED_IN, REQUEST_BODY, CONCURRENT],
      covers: {
        expressAuth: {
          ...authFixed(["handle"]),
          options:
            'fixed: public is ["/"], one exact entry; express-public-paths sweeps the list\'s length',
        },
      },
      inEndToEnd: { ...ADAPTER_IN_END_TO_END, variant: "auth-route" },
      // A Node request is a stream the adapter reads once, and a response is written once, so each sample needs new ones.
      fresh: true,
      setup: async (n, options) => {
        const route = options?.route ?? "auth"
        const middleware = expressAuth(auth(), { public: PUBLIC })
        expectStatus(
          await throughExpress(middleware, nodeExchange(PATH[route])),
          ANSWER[route],
          `expressAuth ${route}`,
        )
        return {
          middleware,
          exchanges: Array.from({ length: n }, () => nodeExchange(PATH[route])),
        }
      },
      run: ({ middleware, exchanges }) =>
        sequentially(exchanges, (exchange) => throughExpress(middleware, exchange)),
    },
    {
      id: "fetch-with-auth",
      name: "withAuth",
      why: "withAuth wraps the whole app on Bun, Deno and any server that hands over a Web Request, so every request pays it: the head converted to test-cap's request, the path match, and under /auth/ the reply converted to a Response with each cookie on its own line. The requests are Web Requests built ahead, so the runtime's own parsing stays out of the figure.",
      poorPerformanceMeans:
        "A tax on all of the app's traffic, public pages included: slower responses and more servers for the same load. Cost that grew with the number of requests served would mean the wrapper keeps something per request.",
      expectedComplexity: "linear",
      complexityReason:
        "Each request does the same fixed work: one head conversion, one path match and at most one call into the core, so n requests cost n times one.",
      variables: [
        REQUESTS,
        {
          name: "route",
          how: "variant",
          description:
            "The session request, a public page and a protected page, as the variants below.",
        },
        NO_SESSION,
      ],
      variants: ROUTE_VARIANTS,
      notCovered: [SIGNED_IN, REQUEST_BODY, CONCURRENT],
      covers: {
        withAuth: {
          ...authFixed(["handle"]),
          handler:
            "fixed: answers one empty 200 Response built ahead, so the figure is the adapter's work and not the app's",
          "options.public":
            'fixed: ["/"], one exact entry; express-public-paths sweeps the length of the same compiled list',
          "options.clientAddress":
            "fixed: returns a constant address, read from memory as Deno's info.remoteAddr.hostname is",
        },
      },
      inEndToEnd: { ...ADAPTER_IN_END_TO_END, variant: "auth-route" },
      setup: async (n, options) => {
        const route = options?.route ?? "auth"
        const handler = withAuth(auth(), () => APP_RESPONSE, { public: PUBLIC, clientAddress })
        const [first] = webRequests(1, PATH[route])
        expectStatus(statusOf(await handler(first)), ANSWER[route], `withAuth ${route}`)
        return { handler, requests: webRequests(n, PATH[route]) }
      },
      run: async ({ handler, requests }) =>
        sequentially(requests, async (req) => statusOf(await handler(req))),
    },
    {
      id: "fetch-auth-routes",
      name: "fetchAuth",
      why: "An app that routes by itself on Bun or Deno hands every request to fetchAuth first, so each pays the check for /auth/, and the session request every page load makes also pays the conversion both ways. The requests are Web Requests built ahead, so the runtime's own parsing stays out of the figure.",
      poorPerformanceMeans:
        "Slower responses on every route of the app, since each request is offered to fetchAuth before the app's own router sees it.",
      expectedComplexity: "linear",
      complexityReason:
        "Each request does the same fixed work: one path check and, under /auth/, one conversion each way and one call into the core, so n requests cost n times one.",
      variables: [
        REQUESTS,
        {
          name: "route",
          how: "variant",
          description: "A path under /auth/ and one outside it, as the variants below.",
        },
        NO_SESSION,
      ],
      variants: [
        ROUTE_VARIANTS[0],
        {
          name: "outside-auth",
          description:
            "GET /account: answered null with the body unread, for the app's own router.",
          options: { route: "protected" },
        },
      ],
      notCovered: [REQUEST_BODY, CONCURRENT],
      covers: {
        fetchAuth: {
          ...authFixed(["handle"]),
          options:
            "fixed: clientAddress returns a constant address, read from memory as Deno's info.remoteAddr.hostname is",
        },
      },
      inEndToEnd: { ...ADAPTER_IN_END_TO_END, variant: "auth-route" },
      setup: async (n, options) => {
        const route = options?.route ?? "auth"
        const serve = fetchAuth(auth(), { clientAddress })
        const [first] = webRequests(1, PATH[route])
        // fetchAuth protects nothing, so a path outside /auth/ is handed on, not refused.
        expectStatus(
          statusOf(await serve(first)),
          route === "auth" ? 200 : PASSED,
          `fetchAuth ${route}`,
        )
        return { serve, requests: webRequests(n, PATH[route]) }
      },
      run: async ({ serve, requests }) =>
        sequentially(requests, async (req) => statusOf(await serve(req))),
    },
    {
      id: "next-auth-handler",
      name: "nextAuthHandler",
      why: "The route handler for app/auth/[...path]/route.ts serves every /auth/ request a Next.js app receives, the session request every page load makes included. Next.js hands it a Web Request, built ahead here, and it converts through test-cap/fetch.",
      poorPerformanceMeans:
        "Slower page loads, since each one waits on the session request, and more server time per visitor.",
      expectedComplexity: "linear",
      complexityReason:
        "Each request does the same fixed work: one path check, one conversion each way and one call into the core, so n requests cost n times one.",
      variables: [
        REQUESTS,
        {
          name: "route",
          how: "fixed",
          value: "GET /auth/session",
          description: "The request every page load makes first, through the GET handler.",
        },
        NO_SESSION,
      ],
      notCovered: [
        {
          name: "the POST handler",
          reason:
            "POST is the same function as GET; a POST adds the body read, which sign-up-body measures through auth.handle.",
        },
        CONCURRENT,
      ],
      covers: { nextAuthHandler: { ...authFixed(["handle"]), ...NO_CLIENT_ADDRESS } },
      inEndToEnd: ADAPTER_IN_END_TO_END,
      setup: async (n) => {
        const { GET } = nextAuthHandler(auth())
        const [first] = webRequests(1, PATH.auth)
        expectStatus(statusOf(await GET(first)), 200, "nextAuthHandler")
        return { GET, requests: webRequests(n, PATH.auth) }
      },
      run: async ({ GET, requests }) =>
        sequentially(requests, async (req) => statusOf(await GET(req))),
    },
    {
      id: "next-proxy",
      name: "nextProxy",
      why: "A Next.js proxy runs before every route its matcher covers, so its cost lands on more requests than any other surface. It never reads the store: it matches the path, looks for a session cookie and builds a redirect.",
      poorPerformanceMeans:
        "Every page and every matched request waits on it, so a slow proxy slows the whole app, including pages that need no session.",
      expectedComplexity: "linear",
      complexityReason:
        "Each request does the same fixed work: one path check, one URL parse, one cookie scan and at most one redirect, so n requests cost n times one.",
      variables: [
        REQUESTS,
        {
          name: "route",
          how: "variant",
          description:
            "A public page, a protected page without a session cookie and one with a cookie, as the variants below.",
        },
      ],
      variants: [
        ROUTE_VARIANTS[1],
        {
          name: "redirect",
          description:
            "GET /account with no session cookie: a 307 to the sign-in page, built on APP_ORIGIN.",
          options: { route: "protected", cookie: false },
        },
        {
          name: "session-cookie",
          description:
            "GET /account with a session cookie: the proxy lets it continue without reading the store.",
          options: { route: "protected", cookie: true },
        },
      ],
      notCovered: [CONCURRENT],
      covers: {
        nextProxy: {
          ...authFixed([]),
          "options.public":
            'fixed: ["/"], one exact entry; express-public-paths sweeps the length of the same compiled list',
          "options.signIn":
            "fixed: absent, so the redirect goes to /auth/sign-in; a custom path is checked once, when the proxy is built",
        },
      },
      inEndToEnd: { ...ADAPTER_IN_END_TO_END, variant: "redirect" },
      setup: (n, options) => {
        const route = options?.route ?? "public"
        const headers = options?.cookie === true ? { Cookie: SESSION_COOKIE } : {}
        const proxy = nextProxy(auth(), { public: PUBLIC })
        const [first] = webRequests(1, PATH[route], headers)
        const wanted = route === "protected" && options?.cookie !== true ? 307 : PASSED
        expectStatus(statusOf(proxy(first)), wanted, `nextProxy ${route}`)
        return { proxy, requests: webRequests(n, PATH[route], headers) }
      },
      run: ({ proxy, requests }) => sequentially(requests, (req) => statusOf(proxy(req))),
    },
    {
      id: "next-server-auth",
      name: "nextServerAuth",
      why: "The authoritative check of a Next.js app: route handlers, server functions and the data-access layer call it whenever they need a session, often several times per request. Each call copies the request's headers from next/headers into test-cap's request before the core reads the cookie.",
      poorPerformanceMeans:
        "Every protected read pays it, sometimes several times per request, so a slow helper slows every page and action that touches data.",
      expectedComplexity: "linear",
      complexityReason:
        "Each call does the same fixed work: one copy of the request's few headers and one call into the core, so n calls cost n times one.",
      variables: [
        REQUESTS,
        {
          name: "helper",
          how: "variant",
          description: "session() and require(), as the variants below.",
        },
        NO_SESSION,
      ],
      variants: [
        {
          name: "session",
          description: "serverAuth.session() with no session cookie: answers null.",
          options: { helper: "session" },
        },
        {
          name: "require",
          description:
            "serverAuth.require() at the default requirement with no session cookie: answers unauthenticated.",
          options: { helper: "require" },
        },
      ],
      notCovered: [SIGNED_IN, CONCURRENT],
      covers: {
        nextServerAuth: {
          ...authFixed(["require", "session"]),
          options:
            "fixed: headers resolves three header lines from memory, as next/headers does, none of them a session cookie",
        },
      },
      inEndToEnd: { ...ADAPTER_IN_END_TO_END, variant: "require" },
      setup: async (n, options) => {
        const serverAuth = nextServerAuth(auth(), { headers: () => Promise.resolve(NEXT_HEADERS) })
        const call =
          options?.helper === "session"
            ? async () => ((await serverAuth.session()) === null ? 401 : 200)
            : async () => ((await serverAuth.require()).outcome === "allow" ? 200 : 401)
        expectStatus(await call(), 401, `nextServerAuth ${String(options?.helper)}`)
        return { call, calls: Array.from({ length: n }, (_, i) => i) }
      },
      run: ({ call, calls }) => sequentially(calls, call),
    },
    {
      id: "tanstack-start-auth",
      name: "tanstackStartAuth",
      why: "Its route handler serves the /auth/$ server route, which every page load reaches for the session, and its session and require helpers run inside server functions next to the data. Each converts a Web Request, built ahead here, to test-cap's request; the route handler also converts the reply back.",
      poorPerformanceMeans:
        "Slower page loads, which wait on the session request, and slower server functions, which call the helpers before touching data.",
      expectedComplexity: "linear",
      complexityReason:
        "Each request does the same fixed work: one head conversion, one call into the core and, for the route handler, one conversion back, so n requests cost n times one.",
      variables: [
        REQUESTS,
        {
          name: "surface",
          how: "variant",
          description: "The route handler and the two helpers, as the variants below.",
        },
        NO_SESSION,
      ],
      variants: [
        {
          name: "route-handler",
          description: "handlers.ANY with GET /auth/session, served by auth.handle.",
          options: { surface: "handler" },
        },
        {
          name: "session",
          description: "session(request) with no session cookie: answers null.",
          options: { surface: "session" },
        },
        {
          name: "require",
          description:
            'require(request, "default") with no session cookie: answers unauthenticated.',
          options: { surface: "require" },
        },
      ],
      notCovered: [SIGNED_IN, REQUEST_BODY, CONCURRENT],
      covers: {
        tanstackStartAuth: { ...authFixed(["handle", "require", "session"]), ...NO_CLIENT_ADDRESS },
      },
      inEndToEnd: { ...ADAPTER_IN_END_TO_END, variant: "route-handler" },
      setup: async (n, options) => {
        const start = tanstackStartAuth(auth())
        const surface = options?.surface ?? "handler"
        const send = {
          handler: async (request) => (await start.handlers.ANY({ request })).status,
          session: async (request) => ((await start.session(request)) === null ? 401 : 200),
          require: async (request) =>
            (await start.require(request, "default")).outcome === "allow" ? 200 : 401,
        }[surface]
        const path = surface === "handler" ? PATH.auth : PATH.protected
        const [first] = webRequests(1, path)
        expectStatus(
          await send(first),
          surface === "handler" ? 200 : 401,
          `tanstackStartAuth ${surface}`,
        )
        return { send, requests: webRequests(n, path) }
      },
      run: ({ send, requests }) => sequentially(requests, send),
    },
    {
      id: "tanstack-start-middleware",
      name: "tanstackStartMiddleware",
      why: "Registered as a global request middleware, it runs on every request a TanStack Start app receives: pages, server routes and server function calls. Each pays the head conversion and the path match before the app runs. The requests are Web Requests built ahead, so the framework's own work stays out of the figure.",
      poorPerformanceMeans:
        "A tax on all of the app's traffic, public pages and server function calls included: slower responses and more servers for the same load.",
      expectedComplexity: "linear",
      complexityReason:
        "Each request does the same fixed work: one head conversion and one path match, plus a refusal converted back when deny by default refuses it, so n requests cost n times one.",
      variables: [
        REQUESTS,
        {
          name: "route",
          how: "variant",
          description:
            "The session request, a public page and a protected page, as the variants below.",
        },
        NO_SESSION,
      ],
      variants: [
        {
          name: "auth-route",
          description:
            "GET /auth/session: handed on to the /auth/$ server route, which tanstack-start-auth measures.",
          options: { route: "auth" },
        },
        ROUTE_VARIANTS[1],
        ROUTE_VARIANTS[2],
      ],
      notCovered: [SIGNED_IN, CONCURRENT],
      covers: {
        tanstackStartMiddleware: {
          ...authFixed([]),
          options:
            'fixed: public is ["/"], one exact entry; express-public-paths sweeps the length of the same compiled list',
        },
      },
      inEndToEnd: { ...ADAPTER_IN_END_TO_END, variant: "public-route" },
      setup: async (n, options) => {
        const route = options?.route ?? "public"
        const middleware = tanstackStartMiddleware(auth(), { public: PUBLIC })
        // `next` stands for the route or server function after the middleware, and answers at once.
        const next = () => PASSED
        const wanted = route === "protected" ? 401 : PASSED
        const [first] = webRequests(1, PATH[route])
        expectStatus(
          statusOf(await middleware({ request: first, next })),
          wanted,
          `tanstackStartMiddleware ${route}`,
        )
        return { middleware, next, requests: webRequests(n, PATH[route]) }
      },
      run: ({ middleware, next, requests }) =>
        sequentially(requests, async (request) => statusOf(await middleware({ request, next }))),
    },
    {
      id: "totp-verify",
      name: "auth.handle (POST /auth/totp/verify)",
      why: "Every password sign-in at the default AAL2 ends with a TOTP code, and so does a TOTP step-up, so this runs on nearly every sign-in. It tries each of the account's TOTP authenticators in turn: a decryption and up to three HMACs each.",
      poorPerformanceMeans:
        "Slower second-factor checks for every user, worst for the people with several authenticator apps; a wrong code always pays for every authenticator.",
      expectedComplexity: "linear",
      complexityReason:
        "verifyTotp lists the account's authenticators and tries each until one accepts, so the work grows with how many the account holds.",
      tiers: [1, 2, 3, 4, 5],
      tiersReason:
        "An account holds at most five TOTP authenticators, so the ladder is every count it can have.",
      variables: [
        {
          name: "authenticators",
          how: "swept",
          description: "Confirmed TOTP authenticators on the account.",
        },
        {
          name: "outcome",
          how: "variant",
          description:
            "A code from the newest authenticator (the last one tried) or a wrong code, as the variants below.",
        },
      ],
      variants: [
        {
          name: "newest-matches",
          description: "The code is the newest authenticator's: every earlier one is tried first.",
          options: { wrong: false },
        },
        {
          name: "wrong-code",
          description: "A code no authenticator accepts: every one is tried.",
          options: { wrong: true },
        },
      ],
      notCovered: [
        {
          name: "replay",
          reason:
            "A replayed time step is refused by the same per-authenticator loop, after the same work.",
        },
      ],
      covers: {},
      inEndToEnd: {
        callsPerOperation: 0,
        variant: "newest-matches",
        description: "Runs once per sign-in, not on every request.",
      },
      fresh: true,
      setup: async (n, options) => {
        const account = await enrolled(n)
        account.clock.advance(30_000)
        const code =
          options?.wrong === true
            ? "000000"
            : await totp(account.secrets.at(-1), account.clock.now())
        return { browser: account.browser, code }
      },
      run: async ({ browser, code }) =>
        (await browser.send("POST", "/auth/totp/verify", { code })).status,
    },
    {
      id: "auth-require",
      name: "auth.require",
      why: "An app calls auth.require next to the data on every route that needs more than the default requirement. It reads the session from the store and recomputes its assurance from the evidence the session holds, with no cache.",
      poorPerformanceMeans:
        "Every protected call pays it, so a slow check slows every sensitive route of the app for as long as the session lives.",
      expectedComplexity: "constant",
      complexityReason:
        "A session keeps only the newest evidence per method and authenticator, so it holds at most one entry per authenticator plus the password, six at most. The assurance is one sorted pass over those entries, and at these counts that pass is dwarfed by fixed work every call does: the session read from the store and the token hash.",
      tiers: [1, 2, 3, 4, 5],
      tiersReason:
        "The evidence is bounded by the account's authenticators, at most five, so the ladder is every count it can have.",
      variables: [
        {
          name: "authenticators",
          how: "swept",
          description:
            "TOTP authenticators on the account, each verified once, so the session holds evidence from each.",
        },
        {
          name: "step-ups",
          how: "fixed",
          value: "one per authenticator",
          description: "Repeated verifications replace their own evidence instead of adding to it.",
        },
        {
          name: "requirement",
          how: "fixed",
          value: "default",
          description: "The default AAL2 requirement, which the session meets.",
        },
      ],
      notCovered: [
        {
          name: "no session",
          reason:
            "A request without a session stops at the cookie parse, which the session-cookies benchmark measures.",
        },
      ],
      covers: {},
      inEndToEnd: {
        callsPerOperation: 0,
        description: "Called by the app on its own protected routes.",
      },
      setup: async (n) => {
        const account = await enrolled(n)
        for (const secret of account.secrets) {
          account.clock.advance(30_000)
          ok(
            await account.browser.send("POST", "/auth/totp/verify", {
              code: await totp(secret, account.clock.now()),
            }),
            "totp verify",
          )
        }
        const cookie = [...account.browser.cookies].map(([k, v]) => `${k}=${v}`).join("; ")
        return { instance: account.instance, req: request("GET", "/account", { Cookie: cookie }) }
      },
      run: async ({ instance, req }) => (await instance.require(req, "default")).outcome,
    },
    {
      id: "store-list-by-owner",
      name: "memoryStore().listByOwner",
      why: "The session list and remote revoke read every session an account owns; an account signed in on many devices has many.",
      poorPerformanceMeans: "Slower session pages and revocation for heavy users.",
      expectedComplexity: "linear",
      complexityReason: "The owner's records are collected in one pass.",
      variables: [
        {
          name: "records",
          how: "swept",
          description: "Records one owner holds in the collection.",
        },
      ],
      notCovered: [
        {
          name: "a SQL store",
          reason:
            "store/sql is not exported until CI runs it against real database servers; its cost is the database's.",
        },
      ],
      covers: {},
      inEndToEnd: {
        callsPerOperation: 0,
        description: "Runs on the session list, not on every request.",
      },
      setup: async (n) => {
        const store = memoryStore()
        for (let i = 0; i < n; i += 1) {
          await store.createUnique("t", {
            collection: "s",
            key: `k${String(i)}`,
            owner: "o",
            expiresAt: null,
            data: i,
          })
        }
        return store
      },
      run: async (store) => (await store.listByOwner("t", "s", "o")).length,
    },
    {
      id: "store-consume-once",
      name: "memoryStore().consumeOnce",
      why: "Every single-use secret (a TOTP time step, a step-up challenge, later a recovery code) is redeemed with consumeOnce, under the store's lock.",
      poorPerformanceMeans:
        "Slower MFA and step-up for everyone once the store holds many records.",
      expectedComplexity: "constant",
      complexityReason: "One keyed lookup and one write, whatever the number of other records.",
      variables: [{ name: "records", how: "swept", description: "Other records in the store." }],
      notCovered: [{ name: "a SQL store", reason: "Not exported in phase 3; see listByOwner." }],
      covers: {},
      inEndToEnd: {
        callsPerOperation: 0,
        description: "Runs on MFA and step-up, not on every request.",
      },
      fresh: true,
      setup: async (n) => {
        const store = memoryStore()
        for (let i = 0; i < n; i += 1) {
          await store.createUnique("t", {
            collection: "c",
            key: `k${String(i)}`,
            owner: null,
            expiresAt: null,
            data: i,
          })
        }
        return store
      },
      run: async (store) => (await store.consumeOnce("t", "c", "k0", 1)) !== null,
    },
    {
      id: "store-increment",
      name: "memoryStore().increment",
      why: "The throttles (phase 4) count every sign-in attempt per account, address and network with increment.",
      poorPerformanceMeans:
        "Throttling that slows as counters accumulate would tax exactly the requests an attack sends.",
      expectedComplexity: "constant",
      complexityReason: "One keyed counter read and write, whatever the number of other counters.",
      variables: [{ name: "counters", how: "swept", description: "Other counters in the store." }],
      notCovered: [{ name: "a SQL store", reason: "Not exported in phase 3; see listByOwner." }],
      covers: {},
      inEndToEnd: { callsPerOperation: 0, description: "Used by the phase 4 throttles." },
      setup: async (n) => {
        const store = memoryStore()
        for (let i = 0; i < n; i += 1) await store.increment("t", `n${String(i)}`, 60_000, 0)
        return store
      },
      run: async (store) => (await store.increment("t", "n0", 60_000, 1)).count,
    },
    {
      id: "store-limiter",
      name: "createStoreLimiter (consume)",
      why: "Every request to /auth is counted through it before its route runs, and so is every guess, mail send and failure; it is the one piece of limiter work on every request.",
      poorPerformanceMeans:
        "A count that slowed as keys accumulate would tax every request, and most of all the ones a flood sends.",
      expectedComplexity: "constant",
      complexityReason:
        "One consume is one atomic increment of one keyed counter, whatever the number of other keys.",
      variables: [
        { name: "keys", how: "swept", description: "Other keys already counted in the store." },
      ],
      notCovered: [
        {
          name: "a SQL store",
          reason: "Not exported in phase 4; the memory store's increment is measured.",
        },
        {
          name: "a block read",
          reason:
            "Every limit test-cap builds counts with blocks off; a block read is one more keyed record read, the same work as one store read.",
        },
      ],
      covers: {
        createStoreLimiter: {
          "options.store":
            "fixed: the memory store, so the figure is the limiter's own work and no database's",
          "options.tenant": "fixed: absent, the default tenant",
          "options.clock": "fixed: absent, the system clock",
          "options.points": "fixed: past any sample count, so no consume is refused",
          "options.duration": "fixed: 60 seconds; the window's length changes no work",
          "options.keyPrefix": "fixed: rate; a prefix is one string join per key",
          "options.blockDuration": "fixed: absent, no block; blocking runs only past points",
          "options.blocks": "fixed: false, as every limit test-cap builds counts",
        },
      },
      inEndToEnd: {
        callsPerOperation: 1,
        description: "One consume per request, for the route's request limit.",
      },
      setup: async (n) => {
        const store = memoryStore()
        const limiter = createStoreLimiter({
          store,
          points: Number.MAX_SAFE_INTEGER,
          duration: 60,
          keyPrefix: "rate",
          blocks: false,
        })
        for (let i = 0; i < n; i += 1) await limiter.consume(`session|198.51.100.${String(i)}`)
        return limiter
      },
      run: async (limiter) => (await limiter.consume("session|198.51.100.0")).consumedPoints,
    },
  ],
})
