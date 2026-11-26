// ADR 0009 §2 through the sign-in route: failures count per account, per account and client, and per client, and
// each key throttles on its own. The account key is the identifier typed, so an address no account holds is
// throttled exactly like one that is.
import { describe, expect, it } from "vitest"
import { account, Browser, inProcess, PASSWORD, testAuth } from "../support/auth.js"

/** A sign-in attempt from `clientAddress`, with a fresh browser each time so no session carries over. */
async function signIn(
  setup: ReturnType<typeof testAuth>,
  identifier: string,
  password: string,
  clientAddress: string,
) {
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  return browser.post("/auth/sign-in", { identifier, password }, { clientAddress })
}

async function failSix(
  setup: ReturnType<typeof testAuth>,
  identifier: string,
  clientAddress: string,
) {
  for (let i = 0; i < 6; i += 1) {
    expect((await signIn(setup, identifier, "wrong password entirely", clientAddress)).status).toBe(
      401,
    )
  }
}

describe("throttle counter keys at the sign-in route", () => {
  it("throttles the account from any client once its failures pass the free ones", async () => {
    const setup = testAuth()
    await account(setup)
    await failSix(setup, "ada@example.com", "192.0.2.1")
    const reply = await signIn(setup, "ada@example.com", PASSWORD, "198.51.100.9")
    expect([reply.status, reply.json, reply.headers.get("retry-after")]).toEqual([
      429,
      { error: "rate-limited" },
      "1",
    ])
  })

  it("throttles the client for every account once its failures pass the free ones", async () => {
    const setup = testAuth()
    await failSix(setup, "ada@example.com", "192.0.2.1")
    const reply = await signIn(setup, "bob@example.com", "anything at all here", "192.0.2.1")
    expect(reply.status).toBe(429)
  })

  it("leaves another account from another client untouched", async () => {
    const setup = testAuth()
    await failSix(setup, "ada@example.com", "192.0.2.1")
    expect(
      (await signIn(setup, "bob@example.com", "anything at all here", "198.51.100.9")).status,
    ).toBe(401)
  })

  it("throttles an address no account holds exactly as one an account holds", async () => {
    const known = testAuth()
    await account(known)
    const unknown = testAuth()
    await failSix(known, "ada@example.com", "192.0.2.1")
    await failSix(unknown, "ada@example.com", "192.0.2.1")
    const replies = await Promise.all(
      [known, unknown].map((setup) =>
        signIn(setup, "ada@example.com", "wrong password entirely", "192.0.2.1"),
      ),
    )
    expect(
      replies.map((reply) => [reply.status, reply.text, reply.headers.get("retry-after")]),
    ).toEqual([
      [429, '{"error":"rate-limited"}', "1"],
      [429, '{"error":"rate-limited"}', "1"],
    ])
  })

  it("lets the person in once the wait ends, and clears the account's count on success", async () => {
    const setup = testAuth()
    await account(setup)
    await failSix(setup, "ada@example.com", "192.0.2.1")
    setup.clock.advance(1_000)
    const success = await signIn(setup, "ada@example.com", PASSWORD, "198.51.100.9")
    expect([success.status, success.json]).toMatchObject([200, { outcome: "step-up" }])
    // The account is clear again: one more failure from a fresh client costs nothing.
    expect(
      (await signIn(setup, "ada@example.com", "wrong password entirely", "198.18.0.1")).status,
    ).toBe(401)
    expect((await signIn(setup, "ada@example.com", PASSWORD, "198.18.0.2")).status).toBe(200)
  })
})
