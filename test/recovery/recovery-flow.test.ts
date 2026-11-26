// ADR 0007 §3 and §4 through the routes: a saved code yields a recovery-only session with no level, revokes the
// account's other sessions, allows only replacing authenticators, and finishing it signs the person out and tells
// the account.
import { describe, expect, it } from "vitest"
import type { EmailMessage } from "../../src/core/email.js"
import { account, body, Browser, inProcess, PASSWORD, testAuth } from "../support/auth.js"
import { codeAt } from "../support/totp.js"

/** An enrolled account at AAL2 with a fresh set of recovery codes. */
async function withCodes(setup: ReturnType<typeof testAuth>) {
  const enrolled = await account(setup)
  // account() leaves `browser` signed out; sign in at AAL2 to make the codes.
  await enrolled.browser.post("/auth/sign-in", {
    identifier: "ada@example.com",
    password: PASSWORD,
  })
  setup.clock.advance(30_000)
  await enrolled.browser.post("/auth/totp/verify", {
    code: await codeAt(enrolled.secret, setup.clock.now()),
  })
  const made = await enrolled.browser.post("/auth/recovery-codes")
  expect(made.status).toBe(200)
  return { ...enrolled, codes: (made.json as { codes: string[] }).codes }
}

async function recover(
  setup: ReturnType<typeof testAuth>,
  code: string,
  identifier = "ada@example.com",
) {
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  return { browser, reply: await browser.post("/auth/recovery", { identifier, code }) }
}

describe("recovery with a saved code", () => {
  it("needs a session at the default requirement to make codes", async () => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const reply = await browser.post("/auth/recovery-codes")
    expect([reply.status, reply.text]).toEqual([401, '{"error":"unauthenticated"}'])
  })

  it("yields a recovery-only session with no level, and revokes every other session of the account", async () => {
    const setup = testAuth()
    const { codes, browser: original } = await withCodes(setup)
    const { browser, reply } = await recover(setup, codes[0] as string)
    expect([reply.status, reply.json]).toEqual([200, { outcome: "recovery-only", returnTo: "/" }])
    expect(body(await browser.get("/auth/session"))["session"]).toMatchObject({
      state: "recovery-only",
      level: null,
    })
    expect(body(await original.get("/auth/session"))["session"]).toBeNull()
  })

  it("answers recovery-only for every requirement, so the session reaches nothing protected", async () => {
    const setup = testAuth()
    const { codes } = await withCodes(setup)
    const { browser } = await recover(setup, codes[0] as string)
    const sessions = await browser.get("/auth/sessions")
    expect([sessions.status, sessions.text]).toEqual([403, '{"error":"recovery-only"}'])
  })

  it("lets the session replace the password and enrol TOTP, still with no level", async () => {
    const setup = testAuth()
    const { codes } = await withCodes(setup)
    const { browser } = await recover(setup, codes[0] as string)
    const password = await browser.post("/auth/password", {
      password: "a brand new passphrase for ada",
    })
    expect([password.status, password.json]).toEqual([
      200,
      { outcome: "recovery-only", returnTo: "/" },
    ])
    const begun = await browser.post("/auth/totp/enrol")
    const { authenticatorId, secret } = begun.json as { authenticatorId: string; secret: string }
    setup.clock.advance(30_000)
    const confirmed = await browser.post("/auth/totp/confirm", {
      authenticatorId,
      code: await codeAt(secret, setup.clock.now()),
    })
    expect([confirmed.status, confirmed.json]).toEqual([
      200,
      { outcome: "recovery-only", returnTo: "/" },
    ])
    expect(body(await browser.get("/auth/session"))["session"]).toMatchObject({
      level: null,
      methods: [],
    })
    const codesAgain = await browser.post("/auth/recovery-codes")
    expect(codesAgain.status).toBe(200)
  })

  it("returns to the prefixed root behind a gateway, after the code and after the new password", async () => {
    const setup = testAuth({ publicBasePath: "/accounts" })
    const { codes } = await withCodes(setup)
    const { browser, reply } = await recover(setup, codes[0] as string)
    const password = await browser.post("/auth/password", {
      password: "a brand new passphrase for ada",
    })
    const home = { outcome: "recovery-only", returnTo: "/accounts/" }
    expect([reply.json, password.json]).toEqual([home, home])
  })

  it("tells the account's address as soon as a code is redeemed, before anything is replaced", async () => {
    const setup = testAuth()
    const { codes } = await withCodes(setup)
    const before = setup.outbox.length
    await recover(setup, codes[0] as string)
    await Promise.resolve()
    const notice = setup.outbox.slice(before)
    expect(notice.map((mail) => [mail.to, mail.subject])).toEqual([
      ["ada@example.com", "A recovery of your account started"],
    ])
    expect(notice[0]?.text).toContain("signed out")
  })

  it("still answers a redeemed code when the mailer fails to send the notice", async () => {
    let box: EmailMessage[] = []
    const setup = testAuth({
      sendEmail: (message) => {
        box.push(message)
        return message.subject.startsWith("A recovery")
          ? Promise.reject(new Error("mailer down"))
          : Promise.resolve()
      },
    })
    box = setup.outbox
    const { codes } = await withCodes(setup)
    const { reply } = await recover(setup, codes[0] as string)
    expect([reply.status, reply.json]).toEqual([200, { outcome: "recovery-only", returnTo: "/" }])
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(box.at(-1)?.subject).toBe("A recovery of your account started")
  })

  it("sends nothing for a code that fails", async () => {
    const setup = testAuth()
    await withCodes(setup)
    const before = setup.outbox.length
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    await browser.post("/auth/recovery", {
      identifier: "ada@example.com",
      code: "AAAAAA-AAAA-AAAA-AAAA-AAAA",
    })
    await Promise.resolve()
    expect(setup.outbox.length).toBe(before)
  })

  it("finishes by signing the person out, with no second notice", async () => {
    const setup = testAuth()
    const { codes } = await withCodes(setup)
    const { browser } = await recover(setup, codes[0] as string)
    const before = setup.outbox.length
    const finished = await browser.post("/auth/recovery/finish")
    expect([finished.status, finished.json]).toEqual([200, { outcome: "unauthenticated" }])
    expect(body(await browser.get("/auth/session"))["session"]).toBeNull()
    await Promise.resolve()
    expect(setup.outbox.length).toBe(before)
    // The new password signs in afresh; the evidence comes from that ceremony, not from recovery.
    const again = new Browser(inProcess(setup.auth))
    await again.start()
    expect(
      (await again.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD }))
        .status,
    ).toBe(200)
  })

  it("refuses to finish a session that is not recovering", async () => {
    const setup = testAuth()
    const { browser } = await withCodes(setup)
    const reply = await browser.post("/auth/recovery/finish")
    expect([reply.status, reply.text]).toEqual([403, '{"error":"not-recovering"}'])
    const anonymous = new Browser(inProcess(setup.auth))
    await anonymous.start()
    expect((await anonymous.post("/auth/recovery/finish")).status).toBe(401)
  })

  it("gives one reply for a wrong code, a used code and an unknown account", async () => {
    const setup = testAuth()
    const { codes } = await withCodes(setup)
    await recover(setup, codes[1] as string)
    const replies = await Promise.all([
      recover(setup, codes[1] as string),
      recover(setup, "AAAAAA-AAAA-AAAA-AAAA-AAAA"),
      recover(setup, codes[2] as string, "nobody@example.com"),
    ])
    expect(replies.map(({ reply }) => [reply.status, reply.text])).toEqual([
      [401, '{"error":"invalid-credentials"}'],
      [401, '{"error":"invalid-credentials"}'],
      [401, '{"error":"invalid-credentials"}'],
    ])
  })
})
