// Attack: sign-up and confirmation resends are used to flood a victim's inbox with mail from the app's domain.
// Stopped by: every send is counted with the atomic `increment`, per destination address (1 a minute, 5 an hour) and
// per IP or IPv6 /64 (20 an hour); over a limit no mail is sent and the reply is unchanged, with the wait time on a
// resend (ADR 0009 §7 and Open 1). Recovery and email sign-in join these counters when they land.
import { describe, expect, it } from "vitest"
import {
  Browser,
  expectOk,
  plainRequest,
  replyOf,
  testAuth,
  type Transport,
} from "../support/auth.js"

type Setup = ReturnType<typeof testAuth>

/** Requests from `clientAddress` (or from no known address), straight into `auth.handle`. */
function from(setup: Setup, clientAddress: string | undefined): Transport {
  return async (request) => {
    const response = await setup.auth.handle({ ...plainRequest(request), clientAddress })
    if (response === null) throw new Error("not an /auth route")
    return replyOf(response)
  }
}

/** Signs up from `clientAddress`, or from no known address when it is `null`. */
async function signUp(
  setup: Setup,
  identifier: string,
  clientAddress: string | null = "203.0.113.7",
) {
  const browser = new Browser(from(setup, clientAddress ?? undefined))
  await browser.start()
  const reply = await expectOk(browser.post("/auth/sign-up", { identifier }))
  return { browser, reply }
}

/** Sign-up's request limit (20 an hour per client) off, so the send limit is what each test meets. */
const MAIL_ONLY = { rateLimit: { rules: { "sign-up": false } } } as const

const SIGN_UP_REPLY = '{"outcome":"enroll","returnTo":"/"}'

describe("email-send-flooding", () => {
  it("sends to one address at most once a minute; a resend inside the minute sends nothing and says how long to wait", async () => {
    const setup = testAuth()
    const { browser } = await signUp(setup, "victim@example.com")
    setup.clock.advance(20_000)
    const early = await browser.post("/auth/email/resend")
    expect([early.status, early.text]).toEqual([200, '{"outcome":"enroll","retryAfterMs":40000}'])
    expect(setup.outbox).toHaveLength(1)
    setup.clock.advance(40_000)
    const due = await browser.post("/auth/email/resend")
    expect(due.text).toBe('{"outcome":"enroll","retryAfterMs":60000}')
    expect(setup.outbox).toHaveLength(2)
  })

  it("sends to one address at most 5 times an hour, whoever signs up with it, and answers sign-up the same", async () => {
    const setup = testAuth()
    const replies: string[] = []
    for (let send = 0; send < 7; send += 1) {
      replies.push((await signUp(setup, "victim@example.com", `198.51.100.${send}`)).reply.text)
      setup.clock.advance(60_000)
    }
    expect(replies).toEqual(Array<string>(7).fill(SIGN_UP_REPLY))
    expect(setup.outbox).toHaveLength(5)
    expect(setup.outbox.every((message) => message.to === "victim@example.com")).toBe(true)
  })

  it("tells a resend over the hourly limit when the hour's window ends", async () => {
    const setup = testAuth()
    const { browser } = await signUp(setup, "victim@example.com")
    for (let send = 0; send < 4; send += 1) {
      setup.clock.advance(60_000)
      await expectOk(browser.post("/auth/email/resend"))
    }
    setup.clock.advance(60_000)
    const over = await browser.post("/auth/email/resend")
    expect(over.text).toBe(`{"outcome":"enroll","retryAfterMs":${60 * 60_000 - 5 * 60_000}}`)
    expect(setup.outbox).toHaveLength(5)
  })

  it("sends at most 20 an hour from one IP address, across addresses", async () => {
    const setup = testAuth(MAIL_ONLY)
    const replies: string[] = []
    for (let send = 0; send < 22; send += 1) {
      replies.push((await signUp(setup, `person${send}@example.com`)).reply.text)
    }
    expect(replies).toEqual(Array<string>(22).fill(SIGN_UP_REPLY))
    expect(setup.outbox.map((message) => message.to)).toEqual(
      Array.from({ length: 20 }, (_, send) => `person${send}@example.com`),
    )
  })

  it("counts the addresses of one IPv6 /64 as one, however they are written", async () => {
    const setup = testAuth(MAIL_ONLY)
    const addresses = [
      "2001:db8:1:2::1",
      "2001:0db8:0001:0002:ffff:ffff:ffff:ffff",
      "2001:DB8:1:2:a:b:c:d",
    ]
    for (let send = 0; send < 21; send += 1) {
      await signUp(setup, `person${send}@example.com`, addresses[send % addresses.length])
    }
    expect(setup.outbox).toHaveLength(20)
    // Another /64 has its own count.
    await signUp(setup, "other@example.com", "2001:db8:1:3::1")
    expect(setup.outbox).toHaveLength(21)
  })

  it("counts an IPv4-mapped IPv6 address as its IPv4 address", async () => {
    const setup = testAuth(MAIL_ONLY)
    for (let send = 0; send < 20; send += 1) {
      await signUp(setup, `person${send}@example.com`, "192.0.2.10")
    }
    await signUp(setup, "mapped@example.com", "::ffff:192.0.2.10")
    expect(setup.outbox).toHaveLength(20)
    await signUp(setup, "loopback@example.com", "::1")
    expect(setup.outbox).toHaveLength(21)
  })

  it("keeps the per-address limits when the adapter supplies no client address", async () => {
    const setup = testAuth()
    for (let send = 0; send < 25; send += 1) {
      await signUp(setup, `person${send}@example.com`, null)
    }
    expect(setup.outbox).toHaveLength(25)
    await signUp(setup, "person0@example.com", null)
    expect(setup.outbox).toHaveLength(25)
  })
})
