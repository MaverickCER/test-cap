// Attack: parallel failing sign-ins each read the old count, so the throttle counts fewer failures than happened.
// Stopped by: the counters use the store's atomic `increment` (ADR 0002, 0009).
import { describe, expect, it } from "vitest"
import { Browser, inProcess, testAuth } from "../support/auth.js"

describe("throttle-counter-race", () => {
  it("counts every one of a burst of parallel failures from one client", async () => {
    const setup = testAuth()
    const attempt = async (n: number) => {
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      return browser.post(
        "/auth/sign-in",
        { identifier: `spray${String(n)}@example.com`, password: "wrong password entirely" },
        { clientAddress: "192.0.2.90" },
      )
    }
    await Promise.all(Array.from({ length: 8 }, (_, i) => attempt(i)))
    // All eight failures counted: the block is the eighth one's (4 s, after 1 s and 2 s for the sixth and seventh),
    // never a shorter one a lost race left behind.
    const next = await attempt(99)
    expect([next.status, next.headers.get("retry-after")]).toEqual([429, "4"])
  })
})
