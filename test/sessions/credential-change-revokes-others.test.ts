// A credential change rotates the session that made it and revokes the account's other sessions (ADR 0006 §7,
// INV-REVOCATION). This file holds the changes phase 4 adds: a new set of recovery codes.
import { describe, expect, it } from "vitest"
import { account, body, Browser, inProcess, PASSWORD, testAuth } from "../support/auth.js"
import { codeAt } from "../support/totp.js"

/** A browser signed in to Ada's account at AAL2, one TOTP time step after the last. */
async function signedInAtAal2(setup: ReturnType<typeof testAuth>, secret: string) {
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  await browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
  setup.clock.advance(30_000)
  const verified = await browser.post("/auth/totp/verify", {
    code: await codeAt(secret, setup.clock.now()),
  })
  expect(verified.status).toBe(200)
  return browser
}

/** The session cookie a browser holds now. */
const sessionCookie = (browser: Browser) => browser.cookies.get("__Host-test-cap") ?? ""

/** What `/auth/session` says about a session token, read from a fresh browser that holds only that token. */
async function sessionOf(setup: ReturnType<typeof testAuth>, token: string) {
  const browser = new Browser(inProcess(setup.auth))
  browser.cookies.set("__Host-test-cap", token)
  return body(await browser.get("/auth/session"))["session"]
}

describe("making a new set of recovery codes", () => {
  it("rotates the session that made it and revokes the account's other sessions", async () => {
    const setup = testAuth()
    const { secret } = await account(setup)
    const maker = await signedInAtAal2(setup, secret)
    const other = await signedInAtAal2(setup, secret)
    const before = sessionCookie(maker)

    const made = await maker.post("/auth/recovery-codes")

    expect(made.status).toBe(200)
    expect((made.json as { codes: string[] }).codes).toHaveLength(10)
    const after = sessionCookie(maker)
    expect(after).not.toBe(before)
    expect(await sessionOf(setup, before)).toBeNull()
    expect(await sessionOf(setup, after)).toMatchObject({ level: "AAL2" })
    expect(body(await other.get("/auth/session"))["session"]).toBeNull()
  })

  it("answers with the next CSRF token, so the rotated session can post again", async () => {
    const setup = testAuth()
    const { secret } = await account(setup)
    const maker = await signedInAtAal2(setup, secret)

    const made = await maker.post("/auth/recovery-codes")
    const again = await maker.post("/auth/recovery-codes")

    expect(made.headers.get("x-csrf-token")).toBeTruthy()
    expect(again.status).toBe(200)
  })
})
