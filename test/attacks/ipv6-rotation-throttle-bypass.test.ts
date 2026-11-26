// Attack: a host rotates through the addresses of its own IPv6 /64, or switches between an IPv4 address and its
// IPv4-mapped IPv6 form, to reset the client counter. Stopped by: the client key is the /64, and a mapped address
// keys as its IPv4 form (ADR 0009 §2).
import { describe, expect, it } from "vitest"
import { Browser, inProcess, testAuth } from "../support/auth.js"

async function attempt(setup: ReturnType<typeof testAuth>, clientAddress: string, n: number) {
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  return browser.post(
    "/auth/sign-in",
    { identifier: `target${String(n)}@example.com`, password: "wrong password entirely" },
    { clientAddress },
  )
}

describe("ipv6-rotation-throttle-bypass", () => {
  it("counts every address of one /64 as one client", async () => {
    const setup = testAuth()
    for (let i = 0; i < 6; i += 1) {
      expect((await attempt(setup, `2001:db8:1:2::${(i + 1).toString(16)}`, i)).status).toBe(401)
    }
    expect((await attempt(setup, "2001:db8:1:2:ffff:ffff:ffff:ffff", 99)).status).toBe(429)
    // The next /64 is another client.
    expect((await attempt(setup, "2001:db8:1:3::1", 100)).status).toBe(401)
  })

  it("counts an IPv4 address and its IPv4-mapped IPv6 form as one client", async () => {
    const setup = testAuth()
    for (let i = 0; i < 6; i += 1) {
      const address = i % 2 === 0 ? "192.0.2.9" : "::ffff:192.0.2.9"
      expect((await attempt(setup, address, i)).status).toBe(401)
    }
    expect((await attempt(setup, "::ffff:c000:209", 99)).status).toBe(429)
  })
})
