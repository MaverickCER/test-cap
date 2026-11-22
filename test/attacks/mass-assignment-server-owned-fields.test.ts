// Attack: a sign-up or account request sets a server-owned field: verified flags, tenant, status, ids.
// Stopped by: the core parses only each route's declared fields and rejects the rest (ADR 0003).
import { describe, expect, it } from "vitest"
import { Browser, inProcess, TENANT, testAuth } from "../support/auth.js"

describe("mass-assignment-server-owned-fields", () => {
  it.each([
    "verified",
    "status",
    "tenant",
    "account",
    "subject",
    "state",
    "evidence",
    "__proto__",
    "constructor",
  ])("refuses a sign-up that sets %s, creating nothing", async (field) => {
    const setup = testAuth()
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const reply = await browser.post("/auth/sign-up", {
      identifier: "ada@example.com",
      [field]: "x",
    })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"undeclared-field"}'])
    expect(setup.events).toEqual([])
    expect(browser.cookies.has("__Host-test-cap")).toBe(false)
    expect(await setup.store.get(TENANT, "identifier", "ada@example.com")).toBeNull()
  })

  it("refuses the same in a form body", async () => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth))
    await browser.start()
    const reply = await browser.postForm("/auth/sign-up", {
      identifier: "ada@example.com",
      verified: "true",
    })
    expect(reply.status).toBe(400)
  })
})
