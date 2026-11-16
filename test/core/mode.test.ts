import { describe, expect, it } from "vitest"
import { base64UrlEncode } from "../../src/core/encoding.js"
import { ConfigError } from "../../src/core/errors.js"
import {
  assertReady,
  checkReadiness,
  isProductionLike,
  parseKeyRing,
  resolveDeploymentMode,
} from "../../src/core/mode.js"

const goodKey = base64UrlEncode(Uint8Array.from({ length: 32 }, (_, i) => (i * 73 + 41) % 256))
const durable = { kind: "sql", durable: true } as const
const memory = { kind: "memory", durable: false } as const

describe("resolveDeploymentMode", () => {
  it("reads the four known values", () => {
    for (const mode of ["production", "staging", "development", "test"] as const) {
      expect(resolveDeploymentMode(mode)).toEqual({ mode, fallback: false })
    }
  })

  it("falls back to production when APP_ENV is missing, empty or unknown", () => {
    for (const value of [undefined, 1, "", "dev", "Production", " production", "prod"]) {
      expect(resolveDeploymentMode(value)).toEqual({ mode: "production", fallback: true })
    }
  })
})

describe("isProductionLike", () => {
  it("treats staging as production", () => {
    expect(isProductionLike("production")).toBe(true)
    expect(isProductionLike("staging")).toBe(true)
    expect(isProductionLike("development")).toBe(false)
    expect(isProductionLike("test")).toBe(false)
  })
})

describe("parseKeyRing", () => {
  it("reads id:base64url entries, the first one current", () => {
    const other = base64UrlEncode(Uint8Array.from({ length: 48 }, (_, i) => (i * 31 + 7) % 256))
    const ring = parseKeyRing("AUTH_ENCRYPTION_KEY", `k2:${goodKey},k1:${other}`)
    expect(ring.problems).toEqual([])
    expect(ring.keys.map((key) => key.id)).toEqual(["k2", "k1"])
    expect(ring.keys[0]?.bytes).toHaveLength(32)
    expect(ring.keys[1]?.bytes).toHaveLength(48)
  })

  it("names every malformed entry", () => {
    const short = base64UrlEncode(new Uint8Array(16).fill(9))
    const { problems, keys } = parseKeyRing(
      "AUTH_CSRF_KEY",
      `nokey,bad id:${goodKey},k1:***,k2:${short},k1:${goodKey}`,
    )
    expect(keys).toEqual([])
    expect(problems).toEqual([
      'AUTH_CSRF_KEY entry 1 is not "id:base64url".',
      "AUTH_CSRF_KEY entry 2 has an invalid key id.",
      "AUTH_CSRF_KEY entry 3 is not valid base64url.",
      "AUTH_CSRF_KEY entry 4 is shorter than 32 bytes.",
      'AUTH_CSRF_KEY entry 5 repeats the key id "k1".',
    ])
  })

  it("refuses an empty value", () => {
    expect(parseKeyRing("AUTH_CSRF_KEY", "")).toEqual({
      keys: [],
      problems: ["AUTH_CSRF_KEY is empty."],
    })
  })

  it("returns no keys when any entry is malformed, even if another is good", () => {
    expect(parseKeyRing("AUTH_CSRF_KEY", `k1:${goodKey},bad`)).toEqual({
      keys: [],
      problems: ['AUTH_CSRF_KEY entry 2 is not "id:base64url".'],
    })
  })

  it("refuses keys that look like defaults: one repeated byte, a counting sequence, a short repeating pattern", () => {
    const repeated = base64UrlEncode(new Uint8Array(32).fill(65))
    const counting = base64UrlEncode(Uint8Array.from({ length: 32 }, (_, i) => i))
    const pattern = base64UrlEncode(
      Uint8Array.from({ length: 32 }, (_, i) => [1, 2, 3, 4][i % 4] ?? 0),
    )
    for (const key of [repeated, counting, pattern]) {
      expect(parseKeyRing("AUTH_AUDIT_KEY", `k:${key}`).problems).toEqual([
        "AUTH_AUDIT_KEY entry 1 looks like an example or default key, not a random one.",
      ])
    }
  })
})

describe("checkReadiness", () => {
  const secrets = { AUTH_ENCRYPTION_KEY: `k1:${goodKey}`, AUTH_CSRF_KEY: `k1:${goodKey}` }

  it("passes a production setup with an HTTPS origin, a durable store and every secret", () => {
    expect(
      checkReadiness({
        mode: "production",
        origin: "https://app.example",
        store: durable,
        secrets,
      }),
    ).toEqual([])
    expect(
      checkReadiness({
        mode: "production",
        origin: "https://app.example:8443",
        store: durable,
        secrets,
      }),
    ).toEqual([])
  })

  it("lists every problem of a production setup at once", () => {
    expect(
      checkReadiness({
        mode: "staging",
        origin: "http://app.example",
        store: memory,
        secrets: { AUTH_ENCRYPTION_KEY: undefined, AUTH_CSRF_KEY: "k1:c2hvcnQ" },
      }),
    ).toEqual([
      "APP_ORIGIN must use https in staging.",
      'The "memory" store keeps nothing across restarts or processes; staging needs a durable store.',
      "AUTH_ENCRYPTION_KEY is missing.",
      "AUTH_CSRF_KEY entry 1 is shorter than 32 bytes.",
    ])
  })

  it("refuses localhost over http in production", () => {
    expect(
      checkReadiness({
        mode: "production",
        origin: "http://localhost:3000",
        store: durable,
        secrets,
      }),
    ).toEqual(["APP_ORIGIN must use https in production."])
  })

  it("refuses an origin that is not a bare origin, in every mode", () => {
    for (const origin of [
      "https://app.example/",
      "https://app.example/path",
      "https://app.example?x",
      "https://user:pass@app.example",
      "not a url",
      "ftp://app.example",
      "https://app.example#x",
    ]) {
      expect(checkReadiness({ mode: "test", origin, store: memory, secrets: {} }), origin).toEqual([
        "APP_ORIGIN must be a bare origin such as https://app.example (scheme, host and optional port).",
      ])
    }
  })

  it("lets development and test use http on a loopback host, the memory store and generated keys", () => {
    for (const origin of ["http://localhost:3000", "http://127.0.0.1:8080", "http://[::1]:3000"]) {
      expect(checkReadiness({ mode: "development", origin, store: memory, secrets: {} })).toEqual(
        [],
      )
    }
  })

  it("lets development leave a secret unset, for keys generated at startup", () => {
    expect(
      checkReadiness({
        mode: "development",
        origin: "http://localhost:3000",
        store: memory,
        secrets: { AUTH_CSRF_KEY: undefined },
      }),
    ).toEqual([])
  })

  it("still refuses http on a non-loopback host in development", () => {
    expect(
      checkReadiness({
        mode: "development",
        origin: "http://dev.example",
        store: memory,
        secrets: {},
      }),
    ).toEqual(["APP_ORIGIN must use https unless the host is localhost, 127.0.0.1 or [::1]."])
  })

  it("still checks a secret that is present in development", () => {
    expect(
      checkReadiness({
        mode: "test",
        origin: "http://localhost",
        store: memory,
        secrets: { AUTH_CSRF_KEY: "garbage" },
      }),
    ).toEqual(['AUTH_CSRF_KEY entry 1 is not "id:base64url".'])
  })
})

describe("checkReadiness with injected sources", () => {
  it("allows a custom clock and random source in test mode only", () => {
    const custom = { clock: true, random: true }
    expect(
      checkReadiness({
        mode: "test",
        origin: "http://localhost",
        store: memory,
        secrets: {},
        custom,
      }),
    ).toEqual([])
    expect(
      checkReadiness({
        mode: "development",
        origin: "http://localhost",
        store: memory,
        secrets: {},
        custom,
      }),
    ).toEqual([
      "A custom Clock is for tests only; development must use the system clock.",
      "A custom RandomSource is for tests only; development must use Web Crypto.",
    ])
  })

  it("names only the source that was replaced", () => {
    expect(
      checkReadiness({
        mode: "production",
        origin: "https://app.example",
        store: durable,
        secrets: {},
        custom: { clock: false, random: true },
      }),
    ).toEqual(["A custom RandomSource is for tests only; production must use Web Crypto."])
  })
})

describe("assertReady", () => {
  it("throws one ConfigError naming every problem", () => {
    try {
      assertReady({ mode: "production", origin: "http://x.example", store: memory, secrets: {} })
      expect.unreachable()
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError)
      expect((error as Error).name).toBe("ConfigError")
      expect((error as ConfigError).problems).toHaveLength(2)
      expect((error as Error).message).toContain("- APP_ORIGIN must use https in production.")
    }
  })

  it("returns quietly when the setup is ready", () => {
    expect(() =>
      assertReady({ mode: "test", origin: "http://localhost", store: memory, secrets: {} }),
    ).not.toThrow()
  })
})
