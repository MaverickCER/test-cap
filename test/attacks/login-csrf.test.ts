// Attack: a cross-site form signs the victim in to the attacker's account (login CSRF).
// Stopped by: CSRF token on sign-in forms; callbacks bound to the browser's own federation transaction (ADR 0011, 0006).
// Federation callbacks arrive in phase 5; this pins the sign-in form.
import { describe, expect, it } from "vitest"
import { Browser, inProcess, PASSWORD, seedAccount, testAuth } from "../support/auth.js"

const attackerCredentials = { identifier: "ada@example.com", password: PASSWORD }

describe("login-csrf", () => {
  it("refuses a cross-site sign-in post, even carrying a token the attacker fetched for themselves", async () => {
    const setup = testAuth()
    await seedAccount(setup, { password: true })
    const attacker = new Browser(inProcess(setup.auth))
    await attacker.start()
    const victim = new Browser(inProcess(setup.auth), "https://evil.example")
    await victim.start()
    const reply = await victim.postForm("/auth/sign-in", {
      ...attackerCredentials,
      csrfToken: attacker.csrf ?? "",
    })
    expect([reply.status, reply.text]).toEqual([403, '{"error":"csrf"}'])
    expect(victim.cookies.has("__Host-test-cap")).toBe(false)
  })

  it("refuses a same-origin-looking post whose token was issued to another browser", async () => {
    const setup = testAuth()
    await seedAccount(setup, { password: true })
    const attacker = new Browser(inProcess(setup.auth))
    await attacker.start()
    const victim = new Browser(inProcess(setup.auth))
    await victim.start()
    victim.csrf = attacker.csrf
    const reply = await victim.post("/auth/sign-in", attackerCredentials)
    expect(reply.status).toBe(403)
    expect(victim.cookies.has("__Host-test-cap")).toBe(false)
  })

  it("refuses a post from a browser that never loaded test-cap, so holds no pre-session cookie", async () => {
    const setup = testAuth()
    await seedAccount(setup, { password: true })
    const attacker = new Browser(inProcess(setup.auth))
    await attacker.start()
    const victim = new Browser(inProcess(setup.auth))
    victim.csrf = attacker.csrf
    expect((await victim.post("/auth/sign-in", attackerCredentials)).status).toBe(403)
  })

  it("signs in a browser whose own form carries its own token", async () => {
    const setup = testAuth()
    await seedAccount(setup, { password: true })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    expect((await browser.post("/auth/sign-in", attackerCredentials)).status).toBe(200)
  })
})
