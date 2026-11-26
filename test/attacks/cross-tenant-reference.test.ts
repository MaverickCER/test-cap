// Attack: a session, account or code from one tenant is used in another. Stopped by: every store operation is scoped
// to one tenant, taken from the configuration, never from the request (ADR 0012).
import { describe, expect, it } from "vitest"
import { memoryStore } from "../../src/store/memory.js"
import {
  aal2,
  account,
  Browser,
  inProcess,
  PASSWORD,
  seedSession,
  testAuth,
} from "../support/auth.js"

describe("cross-tenant-reference", () => {
  it("does not let a session or an account of one tenant act in another tenant over the same store", async () => {
    const store = memoryStore()
    const home = testAuth({ store })
    const other = testAuth({ store, tenant: "other-tenant" })
    await account(home)
    const { token } = await seedSession(home, { subject: "acct-home", evidence: aal2(home.clock) })
    const elsewhere = new Browser(inProcess(other.auth))
    elsewhere.cookies.set("__Host-test-cap", token)
    await elsewhere.start()
    expect((await elsewhere.get("/auth/session")).json).toMatchObject({ session: null })
    const signIn = await elsewhere.post("/auth/sign-in", {
      identifier: "ada@example.com",
      password: PASSWORD,
    })
    expect([signIn.status, signIn.text]).toEqual([401, '{"error":"invalid-credentials"}'])
  })
})
