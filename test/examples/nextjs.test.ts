// examples/nextjs end to end (ADR 0024 §4, Open 4): `next build`, then `next start` on an ephemeral port, then the
// whole journey over real HTTP against the packed test-cap the example installed. The example is its own npm
// project; CI's `examples` job installs it, and without its node_modules this file skips.
import { type ChildProcess, spawn, spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import { createServer } from "node:net"
import path from "node:path"
import { afterAll, beforeAll, describe, expect, it } from "vitest"
import type { Reply } from "../support/auth.js"
import { Client, type HibpStub, hibpStub, PASSWORD, totpCode } from "./support.js"

const example = path.resolve(import.meta.dirname, "../../examples/nextjs")
const next = path.join(example, "node_modules/next/dist/bin/next")
const installed = ["next/package.json", "test-cap/package.json"].every((file) =>
  existsSync(path.join(example, "node_modules", file)),
)

/** A port the OS just handed out and released, for `next start`. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.once("error", reject)
    server.listen(0, "127.0.0.1", () => {
      const address = server.address()
      server.close(() => {
        resolve(typeof address === "object" && address !== null ? address.port : 0)
      })
    })
  })
}

/** The address the journey signs up with. */
const IDENTIFIER = "ada@example.com"

/** One email the example's `sendEmail` received, as its outbox prints it. */
interface OutboxEmail {
  readonly to: string
  readonly subject: string
  readonly text: string
}

/** The outbox the example prints, one `test-cap-outbox <json>` line per email, read from the server's output. */
function outboxOf(output: string): readonly OutboxEmail[] {
  return output
    .split("\n")
    .filter((line) => line.startsWith("test-cap-outbox "))
    .map((line) => JSON.parse(line.slice("test-cap-outbox ".length)) as OutboxEmail)
}

/**
 * The email confirmation step (F08): reads the confirmation code sign-up mailed to `IDENTIFIER` from the example's
 * in-memory outbox, as the person reads their inbox, and posts it to `/auth/email/confirm`.
 */
async function confirmEmail(client: Client, outbox: () => readonly OutboxEmail[]): Promise<Reply> {
  const mail = outbox().filter((email) => email.to === IDENTIFIER)
  expect(mail).toHaveLength(1)
  const code = /Your confirmation code is (\d{6})\./.exec(mail[0]?.text ?? "")?.[1]
  expect(code).toMatch(/^\d{6}$/)
  return client.post("/auth/email/confirm", { code })
}

describe.skipIf(!installed)("example: nextjs", () => {
  let port = 0
  let server: ChildProcess | undefined
  let output = ""
  let origin = ""
  let hibp: HibpStub

  /** A browser on the running app: it keeps cookies and the synchronizer token, and sends the app's origin. */
  const browser = () => new Client(port, origin)

  // `next build` compiles and type-checks the whole app, which takes most of a minute on a busy machine; this hook
  // is the only place it runs.
  beforeAll(async () => {
    port = await freePort()
    origin = `http://127.0.0.1:${port}`
    hibp = await hibpStub()
    const env = {
      ...process.env,
      APP_ENV: "test",
      APP_ORIGIN: origin,
      HIBP_STUB_ORIGIN: hibp.origin,
      NEXT_TELEMETRY_DISABLED: "1",
    }
    const build = spawnSync(process.execPath, [next, "build"], {
      cwd: example,
      env,
      encoding: "utf8",
    })
    if (build.status !== 0) throw new Error(`next build failed:\n${build.stdout}${build.stderr}`)
    server = spawn(process.execPath, [next, "start", "-H", "127.0.0.1", "-p", String(port)], {
      cwd: example,
      env,
    })
    server.stdout?.on("data", (chunk: Buffer) => (output += chunk.toString()))
    server.stderr?.on("data", (chunk: Buffer) => (output += chunk.toString()))
    // Ready when the public home page answers; give up after 120 tries a quarter-second apart.
    for (let attempt = 0; ; attempt += 1) {
      if (attempt === 120) throw new Error(`next start did not answer:\n${output}`)
      const home = await browser()
        .get("/")
        .catch(() => null)
      if (home?.status === 200) break
      await new Promise((resolve) => setTimeout(resolve, 250))
    }
  }, 600_000)

  afterAll(async () => {
    server?.kill()
    await hibp.close()
  })

  /** Fails with the server's output when the reply is not what the step expects. */
  function expectStatus(reply: Reply, status: number): Reply {
    expect(reply.status, `${reply.text}\n${output}`).toBe(status)
    return reply
  }

  it("serves the public home page to anyone", async () => {
    const reply = expectStatus(await browser().get("/"), 200)
    expect(reply.text).toContain("test-cap on Next.js")
  })

  it("refuses every protected route signed out, and the server helper refuses what the proxy lets by", async () => {
    const visitor = browser()
    const page = expectStatus(await visitor.get("/billing"), 307)
    // The proxy redirects to an absolute URL on APP_ORIGIN; Next.js sends a same-origin one as a relative path.
    expect(page.headers.get("location")).toBe("/?returnTo=%2Fbilling")
    expectStatus(await visitor.get("/billing/invoices"), 307)
    // A forged session cookie gets past the proxy, which does not read the store; the helper behind it refuses.
    visitor.cookies.set("__Host-test-cap", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    const forged = expectStatus(await visitor.get("/billing"), 307)
    expect(forged.headers.get("location")).toBe("/?need=unauthenticated&returnTo=%2Fbilling")
    const api = expectStatus(await visitor.get("/billing/invoices"), 401)
    expect(api.json).toEqual({ error: "unauthenticated" })
  })

  it("signs up with a password and TOTP, signs in, steps up, opens /billing and signs out", async () => {
    const user = browser()

    // Sign-up: an account, the emailed code that confirms its address, a password, then a TOTP authenticator, which
    // completes enrolment at AAL2.
    await user.start()
    expect(
      expectStatus(await user.post("/auth/sign-up", { identifier: IDENTIFIER }), 200).json,
    ).toEqual({
      outcome: "enroll",
      returnTo: "/",
    })
    expect(expectStatus(await confirmEmail(user, () => outboxOf(output)), 200).json).toEqual({
      outcome: "enroll",
    })
    expectStatus(await user.post("/auth/password", { password: PASSWORD }), 200)
    const enrolment = expectStatus(await user.post("/auth/totp/enrol"), 200)
    const { authenticatorId, secret } = enrolment.json as {
      authenticatorId: string
      secret: string
    }
    const enrolledAt = Date.now()
    const confirmed = await user.post("/auth/totp/confirm", {
      authenticatorId,
      code: totpCode(secret, enrolledAt),
    })
    expect(expectStatus(confirmed, 200).json).toEqual({ outcome: "allow", returnTo: "/" })
    expect(expectStatus(await user.get("/billing"), 200).text).toContain("INV-0001")

    // Sign-out ends the session.
    expectStatus(await user.post("/auth/sign-out"), 200)
    expect(user.cookies.has("__Host-test-cap")).toBe(false)

    // Sign-in with the password alone: a session that needs a step-up for the default requirement.
    await user.start()
    const signedIn = await user.post("/auth/sign-in", {
      identifier: IDENTIFIER,
      password: PASSWORD,
    })
    expect(expectStatus(signedIn, 200).json).toEqual({ outcome: "step-up", returnTo: "/" })
    const stepUpPage = expectStatus(await user.get("/billing"), 307)
    expect(stepUpPage.headers.get("location")).toBe("/?need=step-up&returnTo=%2Fbilling")
    expect(expectStatus(await user.get("/billing/invoices"), 403).json).toEqual({
      error: "step-up",
    })

    // The second factor: a code from the step after enrolment's, which the replay check accepts.
    const verified = await user.post("/auth/totp/verify", {
      code: totpCode(secret, enrolledAt + 30_000),
    })
    expect(expectStatus(verified, 200).json).toEqual({ outcome: "allow", returnTo: "/" })
    const page = expectStatus(await user.get("/billing"), 200)
    expect(page.text).toContain("Billing")
    expect(expectStatus(await user.get("/billing/invoices"), 200).json).toEqual({
      invoices: ["INV-0001", "INV-0002"],
    })

    // Sign-out again: the old cookie no longer opens anything, and without it the proxy redirects.
    const stale = user.cookies.get("__Host-test-cap") as string
    expectStatus(await user.post("/auth/sign-out"), 200)
    expect(expectStatus(await user.get("/billing"), 307).headers.get("location")).toBe(
      "/?returnTo=%2Fbilling",
    )
    user.cookies.set("__Host-test-cap", stale)
    expectStatus(await user.get("/billing/invoices"), 401)
  })

  it("asked the local HIBP stand-in, never the real service, for the password's range", () => {
    expect(hibp.requests.length).toBeGreaterThan(0)
    for (const request of hibp.requests) expect(request).toMatch(/^\/range\/[0-9A-F]{5}$/)
  })
})
