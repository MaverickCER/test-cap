// Sentinels for the input checks every request passes through: identifiers, client addresses, passwords, HOTP,
// store values, cookies, startup readiness and the HIBP range. Each check asserts the exact answer or message.
import { describe, expect, it } from "vitest"
import { fixedClock, randomBytes, systemRandom } from "../../src/core/clock.js"
import { clientKey } from "../../src/core/client-address.js"
import { constantTimeEqual, utf8Encode } from "../../src/core/encoding.js"
import { TransportError } from "../../src/core/errors.js"
import { normaliseEmail } from "../../src/core/identifier.js"
import { checkReadiness, parseKeyRing, resolveDeploymentMode } from "../../src/core/mode.js"
import { argon2CostProblem } from "../../src/methods/password/argon2.js"
import { type HibpFetch, screenWithHibp } from "../../src/methods/password/hibp.js"
import { checkPasswordLength, normalisePassword } from "../../src/methods/password/rules.js"
import { hotp } from "../../src/methods/totp/hotp.js"
import { emptyResponse } from "../../src/security/headers.js"
import { memoryStore } from "../../src/store/memory.js"
import { assertJson, assertWhole } from "../../src/store/port.js"
import { serializeCookie } from "../../src/transport/cookies.js"
import { base64UrlEncode } from "../../src/core/encoding.js"
import { T0 } from "../support/evidence.js"
import { within } from "../support/within.js"

const COOKIE = { httpOnly: true, sameSite: "Lax" } as const

describe("email identifiers", () => {
  it("normalises a valid address and refuses every malformed one", () => {
    expect(normaliseEmail("Ada@Example.COM")).toBe("ada@example.com")
    const domain = (last: number) => `${"d".repeat(63)}.${"e".repeat(63)}.${"f".repeat(last)}.com`
    const longest = `${"a".repeat(63)}@${domain(58)}`
    expect(longest).toHaveLength(254)
    expect(normaliseEmail(longest)).toBe(longest)
    expect(normaliseEmail(`${"a".repeat(63)}@${domain(59)}`)).toBeNull()
    for (const refused of [
      " ada@example.com",
      "ada@exa mple.com",
      "ada.example.com",
      ".ada@example.com",
      "ada.@example.com",
      "a..da@example.com",
    ]) {
      expect(normaliseEmail(refused), refused).toBeNull()
    }
  })
})

describe("client addresses", () => {
  it("keys IPv4 as itself, mapped IPv6 as its IPv4, other IPv6 by its /64, and anything else as itself", () => {
    const cases: readonly (readonly [string | undefined, string | null])[] = [
      [undefined, null],
      ["192.0.2.1", "192.0.2.1"],
      ["::ffff:192.0.2.10", "192.0.2.10"],
      ["0:0:0:0:0:ffff:192.0.2.10", "192.0.2.10"],
      ["::ffff:c000:20a", "192.0.2.10"],
      ["2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"],
      ["2001:db8::1", "2001:db8:0:0::/64"],
      ["::", "0:0:0:0::/64"],
      ["1:2:3:4:5:6:7::", "1:2:3:4::/64"],
      ["::ffff:192.0.2.255", "192.0.2.255"],
      ["::ffff:192.0.2.256", "::ffff:192.0.2.256"],
      ["1::2::3", "1::2::3"],
      ["1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7:8:9"],
      ["1:2:3:4:5:6:7:8::", "1:2:3:4:5:6:7:8::"],
      ["gggg::1", "gggg::1"],
      ["1:2:3:4::5:6:7:8::9", "1:2:3:4::5:6:7:8::9"],
      ["not-an-address", "not-an-address"],
    ]
    for (const [address, key] of cases) expect(clientKey(address), String(address)).toBe(key)
  })
})

describe("passwords, HOTP and argon2 costs", () => {
  it("accepts a password from its minimum to 256 code points", () => {
    const check = (length: number, alone: boolean) =>
      checkPasswordLength(normalisePassword("x".repeat(length)), { alone })
    expect([check(7, false), check(8, false), check(14, true), check(15, true)]).toEqual([
      "too-short",
      undefined,
      "too-short",
      undefined,
    ])
    expect([check(256, false), check(257, false)]).toEqual([undefined, "too-long"])
  })

  it("computes RFC 4226's first code and refuses a counter that is not a whole number of at least 0", async () => {
    const key = utf8Encode("12345678901234567890")
    expect(await hotp(key, 0, 6)).toBe("755224")
    expect(await hotp(key, 1, 6)).toBe("287082")
    for (const counter of [-1, 1.5]) {
      await expect(hotp(key, counter, 6), String(counter)).rejects.toThrow(
        new RangeError("The HOTP counter must be a whole number of at least 0."),
      )
    }
  })

  it("accepts an argon2id cost only in whole numbers, with memory at least 8 KiB per lane", () => {
    const problem =
      "argon2Cost must be whole numbers: iterations and parallelism at least 1, memoryKiB at least 8 times parallelism."
    const cases = [
      [{ iterations: 1, parallelism: 1, memoryKiB: 8 }, undefined],
      [{ iterations: 1, parallelism: 2, memoryKiB: 16 }, undefined],
      [{ iterations: 1, parallelism: 2, memoryKiB: 15 }, problem],
      [{ iterations: 0, parallelism: 1, memoryKiB: 8 }, problem],
      [{ iterations: 1.5, parallelism: 1, memoryKiB: 8 }, problem],
      [{ iterations: 1, parallelism: 0, memoryKiB: 8 }, problem],
      [{ iterations: 1, parallelism: 1, memoryKiB: 7 }, problem],
    ] as const
    for (const [cost, expected] of cases)
      expect(argon2CostProblem(cost), JSON.stringify(cost)).toBe(expected)
  })
})

describe("store values", () => {
  it("refuses a time or count that is not a whole number at or above its minimum", () => {
    expect(() => {
      assertWhole(-1, "The time")
    }).toThrow(new RangeError("The time must be a whole number of at least 0."))
    expect(() => {
      assertWhole(1.5, "The time")
    }).toThrow(new RangeError("The time must be a whole number of at least 0."))
    expect(() => {
      assertWhole(0, "The window", 1)
    }).toThrow(new RangeError("The window must be a whole number of at least 1."))
    expect(() => {
      assertWhole(0, "The time")
    }).not.toThrow()
  })

  it("accepts plain JSON and names the first value that is not", () => {
    expect(() => {
      assertJson({ a: [1, null, "x", true, { b: 2 }] })
    }).not.toThrow()
    expect(() => {
      assertJson(Number.NaN)
    }).toThrow(new TypeError("data is not a finite number."))
    const holed: unknown[] = [1]
    holed[2] = 2
    expect(() => {
      assertJson(holed)
    }).toThrow(new TypeError("data[1] is missing, so the array is not plain JSON."))
    expect(() => {
      assertJson({ when: new Date(0) })
    }).toThrow(new TypeError("data.when is not plain JSON."))
  })

  it("checks a new record and every part of an update before touching the data", async () => {
    const store = memoryStore()
    await expect(
      store.createUnique("t", { collection: "", key: "k", owner: null, data: 1 }),
    ).rejects.toThrow(new TypeError("The collection must be a non-empty string."))
    expect(await store.createUnique("t", { collection: "c", key: "k", owner: null, data: 1 })).toBe(
      "created",
    )
    await expect(store.update("t", "c", "k", 0, { data: 2 })).rejects.toThrow(
      new RangeError("The expected version must be a whole number of at least 1."),
    )
    await expect(store.update("t", "c", "k", 1, { data: Number.NaN })).rejects.toThrow(
      new TypeError("data is not a finite number."),
    )
    await expect(store.update("t", "c", "k", 1, { expiresAt: 1.5 })).rejects.toThrow(
      new RangeError("expiresAt must be a whole number of at least 0."),
    )
    expect(await store.update("t", "c", "k", 1, { expiresAt: null, data: 3 })).toBe("updated")
    expect(await store.get("t", "c", "k")).toMatchObject({ version: 2, data: 3, expiresAt: null })
    expect(await store.update("t", "c", "k", 2, { expiresAt: T0 })).toBe("updated")
    expect(await store.get("t", "c", "k")).toMatchObject({ version: 3, data: 3, expiresAt: T0 })
    expect(await store.update("t", "c", "k", 3, { data: 4 })).toBe("updated")
    expect(await store.get("t", "c", "k")).toMatchObject({ version: 4, data: 4, expiresAt: T0 })
  })

  it("compares byte strings whole", () => {
    const a = new Uint8Array([1, 2, 3])
    expect(constantTimeEqual(a, new Uint8Array([1, 2, 3]))).toBe(true)
    expect(constantTimeEqual(a, new Uint8Array([1, 2, 4]))).toBe(false)
    expect(constantTimeEqual(a, new Uint8Array([9, 2, 3]))).toBe(false)
    expect(constantTimeEqual(a, new Uint8Array([1, 2]))).toBe(false)
    expect(constantTimeEqual(new Uint8Array([1, 2]), a)).toBe(false)
  })
})

describe("transport and startup", () => {
  it("refuses a cookie name that is not an RFC 6265 token", () => {
    expect(() => serializeCookie("__Host-a b", "v", COOKIE)).toThrow(
      new TypeError("The cookie name is not an RFC 6265 token."),
    )
  })

  it("names a transport error and sets no cookie on an empty response unless asked", () => {
    expect(new TransportError("aborted", "The request was aborted.").name).toBe("TransportError")
    expect(emptyResponse(204).headers.getSetCookie()).toEqual([])
    expect(emptyResponse(204, { cookies: ["a=1"] }).headers.getSetCookie()).toEqual(["a=1"])
  })

  it("refuses a random length that is not a positive integer, and a clock step that is not whole", () => {
    for (const length of [0, 1.5]) {
      expect(() => randomBytes(systemRandom, length), String(length)).toThrow(
        new RangeError("The length must be a positive integer."),
      )
    }
    expect(() => {
      fixedClock(0).advance(0.5)
    }).toThrow(new RangeError("The step must be a whole number of milliseconds."))
  })

  it("resolves APP_ENV, falling back to production", () => {
    expect(resolveDeploymentMode("development")).toEqual({ mode: "development", fallback: false })
    expect(resolveDeploymentMode("prod")).toEqual({ mode: "production", fallback: true })
  })

  it("refuses a counting run as a key and accepts a random-looking one", () => {
    const counting = new Uint8Array(32).map((_, index) => (index + 250) & 0xff)
    const random = new Uint8Array(32).map((_, index) => (index * 37 + 11) & 0xff)
    expect(parseKeyRing("K", `k:${base64UrlEncode(counting)}`).problems).toEqual([
      "K entry 1 looks like an example or default key, not a random one.",
    ])
    expect(parseKeyRing("K", `k:${base64UrlEncode(random)}`).problems).toEqual([])
  })

  it("refuses custom test sources outside test mode, and a non-durable store in production", () => {
    const base = {
      origin: "http://localhost:3000",
      store: { kind: "memory", durable: false },
      secrets: {},
      custom: { clock: true, random: true, argon2Cost: true },
    }
    expect(checkReadiness({ ...base, mode: "test" })).toEqual([])
    expect(checkReadiness({ ...base, mode: "development" })).toEqual([
      "A custom Clock is for tests only; development must use the system clock.",
      "A custom RandomSource is for tests only; development must use Web Crypto.",
      "A custom argon2id cost is for tests only; development must use the ADR 0018 cost.",
    ])
    expect(
      checkReadiness({
        ...base,
        mode: "production",
        origin: "https://app.example",
        secrets: { AUTH_CSRF_KEY: undefined },
        custom: { clock: false, random: false },
      }),
    ).toEqual([
      'The "memory" store keeps nothing across restarts or processes; production needs a durable store.',
      "AUTH_CSRF_KEY is missing.",
    ])
  })
})

describe("the HIBP range check", () => {
  // SHA-1 of "password" is 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8.
  const SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
  const screen = (status: number, body: string, seen: string[] = []) => {
    const fetch: HibpFetch = (url, init) => {
      seen.push(`${init.method} ${url} ${JSON.stringify(init.headers)}`)
      return Promise.resolve({ ok: status === 200, status, text: () => Promise.resolve(body) })
    }
    return screenWithHibp(normalisePassword("password"), fetch)
  }

  it("sends only the first five hex characters, padded, and reads the matching row", async () => {
    const seen: string[] = []
    expect(
      await screen(200, `0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n${SUFFIX}:3\r\n`, seen),
    ).toBe("breached")
    expect(seen).toEqual(['GET https://api.pwnedpasswords.com/range/5BAA6 {"Add-Padding":"true"}'])
    expect(await screen(200, ` ${SUFFIX.toLowerCase()}:3 `)).toBe("breached")
    expect(await screen(200, `${SUFFIX}:0\n0018A45C4D1DEF81644B54AB7F969B88D65:2`)).toBe("clear")
    expect(await screen(200, "0018A45C4D1DEF81644B54AB7F969B88D65:2\nnot a row")).toBe("clear")
  })

  it("is indeterminate for an error status, a body with no rows, a failure or no answer", async () => {
    expect(await screen(503, `${SUFFIX}:3`)).toBe("indeterminate")
    expect(await screen(200, "<html>")).toBe("indeterminate")
    expect(
      await screenWithHibp(normalisePassword("password"), () => Promise.reject(new Error("down"))),
    ).toBe("indeterminate")
    const hung = screenWithHibp(normalisePassword("password"), () => new Promise(() => undefined))
    expect(await within(hung, 3_000)).toBe("indeterminate")
  })
})
