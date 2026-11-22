// The TanStack Start example (examples/tanstack-start) as an end-to-end test: the production build, started on an
// ephemeral port, driven over real HTTP through sign-up, sign-out, sign-in, step-up and sign-out again (ADR 0024).
import { randomUUID } from "node:crypto"
import { afterAll, beforeAll, describe, expect, it } from "vitest"
import type { EmailMessage } from "../../src/core/auth.js"
import { Browser, expectOk, type Reply } from "../support/auth.js"
import { codeAt } from "../support/totp.js"
import {
  type HibpStub,
  hibpStub,
  httpTransport,
  installedMatchesBuild,
  isInstalled,
  runScript,
  start,
  type Started,
} from "./support.js"

const EXAMPLE = "tanstack-start"
/** The app's origin: what `APP_ORIGIN` names and what every request's `Host` says. */
const ORIGIN = "http://localhost:3000"
/** The address the journey signs up with and confirms. */
const IDENTIFIER = "ada@example.com"
/** A fresh password per run; the local HIBP stand-in finds no password breached. */
const PASSWORD = `tanstack start example ${randomUUID()}`
const STEP_MS = 30_000

/** A TOTP code for a time step after `afterStep`, at the current step when that is later (ADR 0027: no replay). */
async function nextCode(
  secret: string,
  afterStep: number,
): Promise<{ code: string; step: number }> {
  const step = Math.max(Math.floor(Date.now() / STEP_MS), afterStep + 1)
  return { code: await codeAt(secret, step * STEP_MS), step }
}

/**
 * Confirms the address the account signed up with (F08): reads the code sign-up mailed to `IDENTIFIER` from the
 * example's in-memory outbox, as the person reads their inbox, and posts it to `/auth/email/confirm`.
 */
async function confirmEmail(browser: Browser, outbox: readonly EmailMessage[]): Promise<void> {
  const mail = outbox.filter((email) => email.to === IDENTIFIER)
  expect(mail).toHaveLength(1)
  const code = /Your confirmation code is (\d{6})\./.exec(mail[0]?.text ?? "")?.[1]
  expect(code).toMatch(/^\d{6}$/)
  const reply = await expectOk(browser.post("/auth/email/confirm", { code }))
  expect(reply.json).toEqual({ outcome: "enroll" })
}

/** A page request as a browser sends it. */
function page(browser: Browser, path: string): Promise<Reply> {
  return browser.send({ method: "GET", path, headers: [["Accept", "text/html"]] })
}

/** A server function call as TanStack Start's client sends it. */
function serverFn(browser: Browser, url: string, method: "GET" | "POST"): Promise<Reply> {
  return browser.send({
    method,
    path: url,
    headers: [
      ["x-tsr-serverFn", "true"],
      ["Origin", ORIGIN],
      ["Accept", "application/json"],
    ],
  })
}

describe.skipIf(!isInstalled(EXAMPLE))("example: tanstack-start", () => {
  let app: Started
  let browser: Browser
  let urls: Record<string, string>
  let hibp: HibpStub

  beforeAll(async () => {
    runScript(EXAMPLE, "build")
    hibp = await hibpStub()
    app = await start(EXAMPLE, {
      APP_ENV: "test",
      APP_ORIGIN: ORIGIN,
      APP_SYSTEM_ID: "billing-web",
      HIBP_STUB_ORIGIN: hibp.origin,
    })
    browser = new Browser(httpTransport(app.port, "localhost:3000"), ORIGIN)
  }, 300_000)

  afterAll(async () => {
    await app.stop()
    await hibp.close()
  })

  it("installed the package this tree builds", () => {
    expect(installedMatchesBuild(EXAMPLE, "tanstack-start.js")).toBe(true)
    expect(installedMatchesBuild(EXAMPLE, "index.js")).toBe(true)
  })

  it("serves the public home page, which names the server function endpoints", async () => {
    const home = await page(browser, "/")
    expect(home.status).toBe(200)
    expect(home.text).toContain("<h1>Welcome</h1>")
    urls = Object.fromEntries(
      [...home.text.matchAll(/data-server-fn="(\w+)">([^<]+)</g)].map((match) => [
        match[1],
        match[2],
      ]),
    ) as Record<string, string>
    expect(Object.keys(urls).sort()).toEqual(["closeAccount", "exportInvoices"])
  })

  it("refuses the protected page and every server function while signed out", async () => {
    const billing = await page(browser, "/billing")
    expect([billing.status, billing.text]).toEqual([401, '{"error":"unauthenticated"}'])
    const exported = await serverFn(browser, urls["exportInvoices"] as string, "GET")
    expect([exported.status, exported.text]).toEqual([401, '{"error":"unauthenticated"}'])
  })

  it("runs the whole journey over HTTP", async () => {
    // Sign up, confirm the address with the emailed code, then a password and TOTP: the session ends at AAL2.
    await browser.start()
    await expectOk(browser.post("/auth/sign-up", { identifier: IDENTIFIER }))
    await confirmEmail(browser, app.outbox())
    await expectOk(browser.post("/auth/password", { password: PASSWORD }))
    const enrolment = await expectOk(browser.post("/auth/totp/enrol"))
    const { authenticatorId, secret } = enrolment.json as {
      authenticatorId: string
      secret: string
    }
    const confirm = await nextCode(secret, -1)
    await expectOk(browser.post("/auth/totp/confirm", { authenticatorId, code: confirm.code }))
    const session = await browser.get("/auth/session")
    const subject = (session.json as { session: { subject: string } }).session.subject

    // The protected page renders for the session's subject.
    const enrolled = await page(browser, "/billing")
    expect(enrolled.status).toBe(200)
    expect(enrolled.text).toContain(`data-subject="${subject}"`)

    // Sign out: the page and the server functions are refused again.
    await expectOk(browser.post("/auth/sign-out"))
    expect((await page(browser, "/billing")).status).toBe(401)

    // Sign in with the password alone: AAL1, below the default requirement, so the answer is step-up.
    await browser.start()
    await expectOk(browser.post("/auth/sign-in", { identifier: IDENTIFIER, password: PASSWORD }))
    const below = await page(browser, "/billing")
    expect([below.status, below.text]).toEqual([403, '{"error":"step-up"}'])
    const belowFn = await serverFn(browser, urls["exportInvoices"] as string, "GET")
    expect([belowFn.status, belowFn.text]).toEqual([403, '{"error":"step-up"}'])

    // Step up with a TOTP code from a later time step than enrolment used.
    const started = await expectOk(browser.post("/auth/step-up/start"))
    const { challenge } = started.json as { challenge: string }
    const stepUp = await nextCode(secret, confirm.step)
    await expectOk(browser.post("/auth/step-up", { challenge, code: stepUp.code }))

    // AAL2 again: the page renders, a server function that checks billing.export allows, and one that checks
    // billing.close (AAL3) answers with the step-up it needs.
    const billing = await page(browser, "/billing")
    expect(billing.status).toBe(200)
    expect(billing.text).toContain(`data-subject="${subject}"`)
    const exported = await serverFn(browser, urls["exportInvoices"] as string, "GET")
    expect(exported.status).toBe(200)
    expect(exported.text).toContain('"allow"')
    expect(exported.text).toContain("inv-2026-001")
    const closed = await serverFn(browser, urls["closeAccount"] as string, "POST")
    expect(closed.status).toBe(200)
    expect(closed.text).toContain('"step-up"')
    expect(closed.text).not.toContain("inv-2026")

    // Sign out: refused once more, page and server function alike.
    await expectOk(browser.post("/auth/sign-out"))
    const after = await page(browser, "/billing")
    expect([after.status, after.text]).toEqual([401, '{"error":"unauthenticated"}'])
    const afterFn = await serverFn(browser, urls["exportInvoices"] as string, "GET")
    expect([afterFn.status, afterFn.text]).toEqual([401, '{"error":"unauthenticated"}'])
  })

  it("asked the local HIBP stand-in, never the real service, for the password's range", () => {
    expect(hibp.requests.length).toBeGreaterThan(0)
    for (const request of hibp.requests) expect(request).toMatch(/^\/range\/[0-9A-F]{5}$/)
  })
})
