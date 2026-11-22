// Attack: sign-in, sign-up or recovery replies differ for existing and missing accounts.
// Stopped by: uniform replies on sign-in, sign-up and recovery (ADR 0009, 0025). Recovery arrives in phase 4; this
// pins sign-in and sign-up.
import { describe, expect, it } from "vitest"
import { Browser, inProcess, PASSWORD, type Reply, seedAccount, testAuth } from "../support/auth.js"

/** Everything a client can compare, with the per-session random values masked. */
function view(reply: Reply) {
  const headers = [...reply.headers.entries()].map(([name, value]) =>
    name === "set-cookie" || name === "x-csrf-token"
      ? [name, value.replace(/[A-Za-z0-9_-]{43}/g, "<random>").replace(/\.\d+\./, ".<t>.")]
      : [name, value],
  )
  return { status: reply.status, body: reply.text, headers }
}

describe("user-enumeration-responses", () => {
  it("gives sign-in one reply, byte for byte, for every way the account can be missing or wrong", async () => {
    const setup = testAuth()
    await seedAccount(setup, { password: true })
    await seedAccount(setup, { identifier: "nopass@example.com" })
    // A sign-up that set a password but never redeemed its confirmation code.
    await seedAccount(setup, {
      password: true,
      identifier: "pending@example.com",
      confirmed: false,
    })
    const replies = []
    for (const [identifier, password] of [
      ["ada@example.com", "a wrong password"],
      ["missing@example.com", PASSWORD],
      ["nopass@example.com", PASSWORD],
      ["pending@example.com", PASSWORD],
    ]) {
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      replies.push(view(await browser.post("/auth/sign-in", { identifier, password })))
    }
    expect(replies[0]?.status).toBe(401)
    for (const reply of replies) expect(reply).toEqual(replies[0])
  })

  it("gives sign-up one reply for a new address and one an account already holds", async () => {
    const setup = testAuth()
    await seedAccount(setup, { password: true, totp: true })
    const replies = []
    for (const identifier of ["ada@example.com", "fresh@example.com", "ADA@example.com"]) {
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      replies.push(view(await browser.post("/auth/sign-up", { identifier })))
    }
    expect(replies[0]?.status).toBe(200)
    for (const reply of replies) expect(reply).toEqual(replies[0])
  })
})
