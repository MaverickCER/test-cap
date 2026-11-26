// Attack: recovering an account with a code or a mailbox comes out holding the account's level. Stopped by: recovery
// yields the recovery-only state, never evidence or a level; the level comes only from signing in again (ADR 0007).
import { describe, expect, it } from "vitest"
import { account, body, Browser, inProcess, PASSWORD, testAuth } from "../support/auth.js"
import { codeAt } from "../support/totp.js"

describe("recovery-below-account-level", () => {
  it("leaves a recovered AAL2 account's session with no level and no access to what needs one", async () => {
    const setup = testAuth()
    const { browser, secret } = await account(setup)
    await browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
    setup.clock.advance(30_000)
    await browser.post("/auth/totp/verify", { code: await codeAt(secret, setup.clock.now()) })
    const { codes } = (await browser.post("/auth/recovery-codes")).json as { codes: string[] }
    const recovering = new Browser(inProcess(setup.auth))
    await recovering.start()
    await recovering.post("/auth/recovery", { identifier: "ada@example.com", code: codes[0] })
    const session = body(await recovering.get("/auth/session"))["session"]
    expect(session).toMatchObject({ state: "recovery-only", level: null, methods: [] })
    for (const path of ["/auth/sessions"]) {
      expect((await recovering.get(path)).text).toBe('{"error":"recovery-only"}')
    }
    expect((await recovering.post("/auth/step-up/start")).status).toBe(403)
  })
})
