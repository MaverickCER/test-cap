// Attack: a client sends its own X-Forwarded-For, or prepends its own Forwarded element, to pick the throttle key of
// every attempt.
// Stopped by: the header is read only when the socket peer is a declared proxy, from the right, one element at a time
// (ADR 0009 §5).
import { describe, expect, it } from "vitest"
import { Browser, inProcess, testAuth } from "../support/auth.js"

async function attempt(
  setup: ReturnType<typeof testAuth>,
  clientAddress: string,
  forwarded: string,
  headers: readonly (readonly [string, string])[] = [["X-Forwarded-For", forwarded]],
) {
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  return browser.post(
    "/auth/sign-in",
    { identifier: `victim${forwarded}@example.com`, password: "wrong password entirely" },
    { clientAddress, headers },
  )
}

describe("spoofed-forwarded-for", () => {
  it("still counts every attempt against the real socket when the client forges the header", async () => {
    const setup = testAuth()
    for (let i = 0; i < 6; i += 1) {
      expect((await attempt(setup, "192.0.2.66", `198.51.100.${String(i)}`)).status).toBe(401)
    }
    // Six different forged addresses, six different accounts: the one real client is throttled anyway.
    expect((await attempt(setup, "192.0.2.66", "198.51.100.200")).status).toBe(429)
  })

  it("reads the header behind a declared proxy, so clients behind one proxy are told apart", async () => {
    const setup = testAuth({ trustedProxies: ["10.0.0.1"] })
    for (let i = 0; i < 6; i += 1) {
      expect((await attempt(setup, "10.0.0.1", "198.51.100.1")).status).toBe(401)
    }
    expect((await attempt(setup, "10.0.0.1", "198.51.100.1")).status).toBe(429)
    expect((await attempt(setup, "10.0.0.1", "198.51.100.2")).status).toBe(401)
  })

  it("reads only the header the app named, so a forged copy of the other one changes nothing", async () => {
    const setup = testAuth({ trustedProxies: ["10.0.0.1"], forwardedHeader: "forwarded" })
    // The proxy sets Forwarded; the client adds its own X-Forwarded-For, which the proxy passes through.
    for (let i = 0; i < 6; i += 1) {
      const reply = await attempt(setup, "10.0.0.1", String(i), [
        ["X-Forwarded-For", `203.0.113.${String(i)}`],
        ["Forwarded", "for=198.51.100.1"],
      ])
      expect(reply.status).toBe(401)
    }
    const blocked = await attempt(setup, "10.0.0.1", "x", [
      ["X-Forwarded-For", "203.0.113.250"],
      ["Forwarded", "for=198.51.100.1"],
    ])
    expect(blocked.status).toBe(429)
    const other = await attempt(setup, "10.0.0.1", "y", [["Forwarded", 'for="[2001:db8::7]:443"']])
    expect(other.status).toBe(401)
  })

  it("counts a client that prepends its own Forwarded elements, well-formed or not, under the address its proxy appended", async () => {
    const setup = testAuth({ trustedProxies: ["10.0.0.1"], forwardedHeader: "forwarded" })
    const prepended = (n: number) =>
      [`for=203.0.113.${String(n)}`, `for="203.0.113.${String(n)}`, `for=203.0.113.${String(n)};;`][
        n % 3
      ] as string
    // The client sends Forwarded: <its own element>; the proxy appends the address it received the request from.
    for (let i = 0; i < 6; i += 1) {
      const reply = await attempt(setup, "10.0.0.1", String(i), [
        ["Forwarded", `${prepended(i)}, for=198.51.100.1`],
      ])
      expect(reply.status, prepended(i)).toBe(401)
    }
    const blocked = await attempt(setup, "10.0.0.1", "x", [
      ["Forwarded", `${prepended(6)}, for=198.51.100.1`],
    ])
    expect(blocked.status).toBe(429)
    // Another client behind the same proxy keeps its own count.
    const other = await attempt(setup, "10.0.0.1", "y", [["Forwarded", "for=198.51.100.2"]])
    expect(other.status).toBe(401)
  })
})
