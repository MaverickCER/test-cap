// Attack: a botnet tries breached username and password pairs across many accounts, once each, so no per-account
// counter fires. Stopped by: the client counter throttles one address across accounts, and the detector sends a client
// that fails on many accounts to the app's challenge (ADR 0009 §2, §4).
import { describe, expect, it } from "vitest"
import { DEFAULT_MESSAGES } from "../../src/forms/model.js"
import { account, Browser, inProcess, PASSWORD, testAuth } from "../support/auth.js"

async function attempt(
  setup: ReturnType<typeof testAuth>,
  identifier: string,
  password: string,
  clientAddress: string,
) {
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  return browser.post("/auth/sign-in", { identifier, password }, { clientAddress })
}

describe("credential-stuffing", () => {
  it("throttles one address spraying pairs across many accounts, before it reaches a real one", async () => {
    const setup = testAuth()
    await account(setup)
    for (let i = 0; i < 6; i += 1) {
      expect(
        (await attempt(setup, `leak${String(i)}@example.com`, "pair from a breach", "192.0.2.80"))
          .status,
      ).toBe(401)
    }
    // The breached pair that would work arrives too late: the address is throttled across accounts.
    expect((await attempt(setup, "ada@example.com", PASSWORD, "192.0.2.80")).status).toBe(429)
  })

  it("flags a spray with the default throttle, counting the attempts the client's throttle refused", async () => {
    const setup = testAuth({ rateLimit: false, challengeHook: () => false })
    await account(setup)
    const start = setup.clock.now()
    const statuses: number[] = []
    // One address tries a breached pair on a new identifier each time, waiting out every Retry-After it is given.
    for (let i = 0; i < 40 && !statuses.includes(403); i += 1) {
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      const reply = await browser.post(
        "/auth/sign-in",
        { identifier: `leak${String(i)}@example.com`, password: "pair from a breach" },
        { clientAddress: "192.0.2.80" },
      )
      statuses.push(reply.status)
      if (reply.status === 429) setup.clock.advance(Number(reply.headers.get("retry-after")) * 1000)
    }
    // The 21st identifier is the first after 20 distinct ones, all inside the detector's 15 minutes.
    expect(statuses).toHaveLength(21)
    expect(statuses.at(-1)).toBe(403)
    expect(setup.clock.now() - start).toBeLessThan(15 * 60_000)
  })

  it("sends a client that failed on many accounts to the app's challenge, even with a working pair", async () => {
    const setup = testAuth({
      stuffing: { distinctAccounts: 4 },
      throttle: { freeFailures: 50 },
      challengeHook: ({ request }) => request.headers.get("x-human") === "yes",
    })
    await account(setup)
    for (let i = 0; i < 4; i += 1)
      await attempt(setup, `leak${String(i)}@example.com`, "pair from a breach", "192.0.2.81")
    expect((await attempt(setup, "ada@example.com", PASSWORD, "192.0.2.81")).text).toBe(
      '{"error":"challenge-required"}',
    )
    // Another address is not flagged.
    expect((await attempt(setup, "ada@example.com", PASSWORD, "192.0.2.82")).status).toBe(200)
  })

  it("tells a flagged person on the default sign-in page that a check is needed, not that the server failed", async () => {
    const setup = testAuth({
      stuffing: { distinctAccounts: 4 },
      throttle: { freeFailures: 50 },
      challengeHook: () => false,
    })
    await account(setup)
    for (let i = 0; i < 4; i += 1)
      await attempt(setup, `leak${String(i)}@example.com`, "pair from a breach", "192.0.2.83")
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const page = await browser.send({
      method: "POST",
      path: "/auth/sign-in",
      headers: [
        ["Origin", browser.origin],
        ["Accept", "text/html"],
        ["Content-Type", "application/x-www-form-urlencoded"],
      ],
      body: new URLSearchParams({
        identifier: "ada@example.com",
        password: PASSWORD,
        csrfToken: browser.csrf ?? "",
      }).toString(),
      clientAddress: "192.0.2.83",
    })
    expect(page.status).toBe(403)
    expect(page.text).toContain(DEFAULT_MESSAGES.challengeRequired)
    expect(page.text).not.toContain(DEFAULT_MESSAGES.unexpected)
  })
})
