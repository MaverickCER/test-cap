// Attack: a deprovisioned account signs in again, or proves a factor from a session that is still live in the moment
// between disabling the account and revoking its sessions. Stopped by: every ceremony checks the account's status
// before producing evidence (ADR 0012).
import { describe, expect, it } from "vitest"
import { ACCOUNT_COLLECTION, deactivateAccount } from "../../src/core/accounts.js"
import { memoryStore } from "../../src/store/memory.js"
import {
  aal1,
  account,
  body,
  Browser,
  hookedStore,
  inProcess,
  PASSWORD,
  seedAccount,
  seedSession,
  TENANT,
  testAuth,
} from "../support/auth.js"
import { codeAt } from "../support/totp.js"

describe("deprovisioned-account-signs-in", () => {
  it("refuses the right password of a deprovisioned account, with the reply any wrong one gets", async () => {
    const setup = testAuth()
    const { subject } = await account(setup)
    await setup.auth.admin.deprovision(subject)
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const reply = await browser.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    expect([reply.status, reply.text]).toEqual([401, '{"error":"invalid-credentials"}'])
  })
})

type Secret = { readonly password: string } | { readonly code: string }

/**
 * Posts `secret` from a live AAL1 session to `path`. With `race`, the account is disabled just before the ceremony's own
 * status read: the second account read of the request, after the session's.
 */
async function prove(
  path: "/auth/totp/verify" | "/auth/step-up",
  secretOf: (totpSecret: string, now: number) => Promise<Secret>,
  race: boolean,
) {
  const inner = memoryStore()
  const state = { armed: false, accountReads: 0, subject: "", now: 0 }
  const store = hookedStore(inner, async (operation, args) => {
    if (!state.armed || operation !== "get" || args[1] !== ACCOUNT_COLLECTION) return
    state.accountReads += 1
    if (state.accountReads === 2) {
      expect(await deactivateAccount(inner, TENANT, state.subject, state.now)).toBe(true)
    }
  })
  const setup = testAuth({ store })
  const { subject, secret } = await seedAccount(setup, { password: true, totp: true })
  const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
  const fields: Record<string, string> = {}
  if (path === "/auth/step-up") {
    fields["challenge"] = (
      body(await browser.post("/auth/step-up/start")) as { challenge: string }
    )["challenge"]
  }
  Object.assign(state, { armed: race, subject, now: setup.clock.now() })
  const reply = await browser.post(path, {
    ...fields,
    ...(await secretOf(secret ?? "", setup.clock.now())),
  })
  state.armed = false
  return { status: reply.status, text: reply.text, raced: state.accountReads >= 2 }
}

const rightCode = async (secret: string, now: number) => ({ code: await codeAt(secret, now) })
const wrongCode = async (secret: string, now: number) => {
  const code = await codeAt(secret, now)
  return { code: code === "000000" ? "111111" : "000000" }
}
const rightPassword = () => Promise.resolve({ password: PASSWORD })
const wrongPassword = () => Promise.resolve({ password: `${PASSWORD} wrong` })

describe("a deprovisioned account's saved recovery code", () => {
  it("redeems nothing, with the reply any wrong code gets", async () => {
    const setup = testAuth()
    const { secret, subject } = await account(setup)
    const owner = new Browser(inProcess(setup.auth))
    await owner.start()
    await owner.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
    setup.clock.advance(30_000)
    await owner.post("/auth/totp/verify", { code: await codeAt(secret, setup.clock.now()) })
    const { codes } = (await owner.post("/auth/recovery-codes")).json as { codes: string[] }
    await setup.auth.admin.deprovision(subject)
    const recovering = new Browser(inProcess(setup.auth))
    await recovering.start()
    const reply = await recovering.post("/auth/recovery", {
      identifier: "ada@example.com",
      code: codes[0],
    })
    expect([reply.status, reply.text]).toEqual([401, '{"error":"invalid-credentials"}'])
    expect(body(await recovering.get("/auth/session"))["session"]).toBeNull()
  })
})

describe("an account disabled while its request is in flight", () => {
  it("answers the right TOTP code of an account disabled mid-request as it answers a wrong one", async () => {
    const wrong = await prove("/auth/totp/verify", wrongCode, false)
    const raced = await prove("/auth/totp/verify", rightCode, true)
    expect(wrong.status).toBe(401)
    expect(raced.raced).toBe(true)
    expect([raced.status, raced.text]).toEqual([wrong.status, wrong.text])
  })

  it("answers a step-up with the right password of an account disabled mid-request as it answers a wrong one", async () => {
    const wrong = await prove("/auth/step-up", wrongPassword, false)
    const raced = await prove("/auth/step-up", rightPassword, true)
    expect(wrong.status).toBe(401)
    expect(raced.raced).toBe(true)
    expect([raced.status, raced.text]).toEqual([wrong.status, wrong.text])
  })

  it("answers a step-up with the right TOTP code of an account disabled mid-request as it answers a wrong one", async () => {
    const wrong = await prove("/auth/step-up", wrongCode, false)
    const raced = await prove("/auth/step-up", rightCode, true)
    expect(wrong.status).toBe(401)
    expect(raced.raced).toBe(true)
    expect([raced.status, raced.text]).toEqual([wrong.status, wrong.text])
  })
})
