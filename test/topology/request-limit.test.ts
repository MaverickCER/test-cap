// The request limiter through every adapter (ADR 0009 §8, ADR 0024): the same requests get the same counts, the same
// 429 and the same Retry-After through Express (a real loopback socket), fetch, Next.js and TanStack Start, directly
// and behind a trusted proxy.
import { describe, expect, it } from "vitest"
import type { AuthConfig } from "../../src/core/auth.js"
import { testAuth } from "../support/auth.js"
import { within } from "../support/within.js"
import { DRIVERS, PEER } from "./drivers.js"

interface Outcome {
  readonly statuses: readonly number[]
  readonly retryAfter: string | null
  readonly text: string
  readonly page: boolean
}

/** Runs one script through one adapter and returns what it saw. */
async function run(
  driver: (typeof DRIVERS)[number],
  config: Partial<AuthConfig<string>>,
  headersFor: (n: number) => readonly (readonly [string, string])[],
): Promise<Outcome> {
  const setup = testAuth(config)
  const opened = await driver.open(setup.auth, PEER)
  const close = opened.close
  /** Each exchange bounded, so a mutant that leaves a response open fails in seconds, not at the test timeout. */
  const transport: typeof opened.transport = (outgoing) => within(opened.transport(outgoing))
  try {
    const statuses: number[] = []
    for (let n = 0; n < 12; n += 1) {
      statuses.push(
        (await transport({ method: "POST", path: "/auth/sign-in", headers: headersFor(n) })).status,
      )
    }
    const over = await transport({ method: "POST", path: "/auth/sign-in", headers: headersFor(0) })
    const page = await transport({
      method: "POST",
      path: "/auth/sign-in",
      headers: [
        ...headersFor(0),
        ["Origin", "https://app.example"],
        ["Accept", "text/html"],
        ["Content-Type", "application/x-www-form-urlencoded"],
      ],
      body: "identifier=a%40example.com&password=x",
    })
    return {
      statuses,
      retryAfter: over.headers.get("retry-after"),
      text: over.text,
      page:
        page.status === 429 && page.text.includes("Too many attempts. Try again in 10 seconds."),
    }
  } finally {
    await close()
  }
}

describe("the request limiter through every adapter", () => {
  it("answers the same counts, 429 and Retry-After through express, fetch, next and tanstack-start", async () => {
    const outcomes: Record<string, Outcome> = {}
    for (const driver of DRIVERS) outcomes[driver.name] = await run(driver, {}, () => [])
    const expected: Outcome = {
      statuses: [...Array<number>(10).fill(403), 429, 429],
      retryAfter: "10",
      text: '{"error":"rate-limited"}',
      page: true,
    }
    expect(outcomes).toEqual(Object.fromEntries(DRIVERS.map((driver) => [driver.name, expected])))
  })

  it("counts each forwarded client on its own behind a trusted proxy, the same through every adapter", async () => {
    const outcomes: Record<string, Outcome> = {}
    for (const driver of DRIVERS) {
      outcomes[driver.name] = await run(driver, { trustedProxies: [PEER] }, (n) => [
        ["X-Forwarded-For", n % 2 === 0 ? "198.51.100.1" : "198.51.100.2"],
      ])
    }
    // Twelve requests split over two clients stay under each client's 10; the 13th is the first client's 7th.
    const expected: Outcome = {
      statuses: Array<number>(12).fill(403),
      retryAfter: null,
      text: '{"error":"csrf"}',
      page: false,
    }
    expect(outcomes).toEqual(Object.fromEntries(DRIVERS.map((driver) => [driver.name, expected])))
  })
})
