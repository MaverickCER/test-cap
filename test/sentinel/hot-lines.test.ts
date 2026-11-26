// Sentinels for the hot lines whose mutants outlived the whole suite under load in the phase 4 gate: account and
// identifier reads, the limit store's key naming, the assurance windows, HOTP's counter, cookie values, the memory
// store's argument checks, the HIBP timer and the production default for a client address. Each asserts one exact
// answer, so a mutant there fails here in milliseconds (vitest.config.ts runs test/sentinel/ first).
import { createHash } from "node:crypto"
import { describe, expect, it, vi } from "vitest"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import {
  ACCOUNT_COLLECTION,
  accountActive,
  IDENTIFIER_COLLECTION,
  identifierValues,
  resolveConfirmed,
  UNCONFIRMED_IDENTIFIER_COLLECTION,
} from "../../src/core/accounts.js"
import { fetchAuth } from "../../src/adapters/fetch/index.js"
import { createAuth } from "../../src/core/auth.js"
import { fixedClock, randomDigits, sequenceRandom } from "../../src/core/clock.js"
import { ConfigError, TransportError } from "../../src/core/errors.js"
import { normaliseEmail } from "../../src/core/identifier.js"
import { screenWithHibp } from "../../src/methods/password/hibp.js"
import { normalisePassword } from "../../src/methods/password/rules.js"
import { hotp } from "../../src/methods/totp/hotp.js"
import { base32Encode } from "../../src/methods/totp/method.js"
import { findStep } from "../../src/methods/totp/totp.js"
import { CLIENT_SCRIPT, pageAssets, STYLESHEET } from "../../src/pages/assets.js"
import { createFailureCeiling } from "../../src/security/ceiling.js"
import { limitStore } from "../../src/security/limit-store.js"
import { LIMIT_BLOCK_COLLECTION } from "../../src/security/store-limiter.js"
import { runAuthStoreConformance } from "../../src/conformance/index.js"
import { memoryStore } from "../../src/store/memory.js"
import { atomically, type StoreOperations } from "../../src/store/port.js"
import { readCookie, serializeCookie } from "../../src/transport/cookies.js"
import { singleHeader } from "../../src/transport/headers.js"
import { matchAuthPath, rawPath } from "../../src/transport/path.js"
import { discardEmail, ENV, hibpClear, keyRing, ORIGIN } from "../support/auth.js"
import { hardwareKey, password, T0, totp } from "../support/evidence.js"
import { setup, TENANT } from "../support/sessions.js"

/** The RFC 4226 Appendix D key. */
const RFC_KEY = new TextEncoder().encode("12345678901234567890")

describe("account and identifier reads", () => {
  it("reads an account with no record as inactive", async () => {
    expect(await accountActive(memoryStore(), TENANT, "nobody")).toBe(false)
  })

  it("lists only string identifier values, skipping a record with no data or another value", async () => {
    const store = memoryStore()
    const owner = "acct-1"
    for (const [key, data] of [
      ["a", { value: "ada@example.com" }],
      ["b", null],
      ["c", { value: 5 }],
    ] as const) {
      await store.createUnique(TENANT, {
        collection: UNCONFIRMED_IDENTIFIER_COLLECTION,
        key,
        owner,
        data,
      })
    }
    expect(await identifierValues(store, TENANT, owner)).toEqual(["ada@example.com"])
  })

  it("refuses an email whose domain carries a URL part, or does not parse as a host", () => {
    for (const refused of [
      "ada@example.com/x",
      "ada@example.com?x",
      "ada@example.com#x",
      "ada@b@example.com",
      "ada@example.com%41",
      "ada@exa^mple.com",
      "ada@exa|mple.com",
    ]) {
      expect(normaliseEmail(refused), refused).toBeNull()
    }
  })
})

describe("the limit store", () => {
  it("names a limit block's key, leaves every other record's key, and passes non-function members through", async () => {
    const inner = memoryStore()
    const named = limitStore(inner, (key) => Promise.resolve(`named:${key}`))
    for (const collection of [LIMIT_BLOCK_COLLECTION, "other"]) {
      await named.createUnique(TENANT, { collection, key: "k", owner: null, data: 1 })
    }
    expect(await inner.get(TENANT, LIMIT_BLOCK_COLLECTION, "named:k")).not.toBeNull()
    expect(await inner.get(TENANT, LIMIT_BLOCK_COLLECTION, "k")).toBeNull()
    expect(await inner.get(TENANT, "other", "k")).not.toBeNull()
    expect(await inner.get(TENANT, "other", "named:k")).toBeNull()
    expect([named.kind, named.durable]).toEqual([inner.kind, inner.durable])
  })
})

describe("the assurance windows", () => {
  const policy = defineAuthPolicy({
    version: "1",
    requirements: {
      "keys.rotate": { level: "AAL2", phishingResistant: true },
      "billing.pay": { level: "AAL2", multiFactorWithinMs: 1_000 },
    },
  })
  const session = (evidence: ReturnType<typeof password>[], now: number) => ({
    subject: "acct-1",
    state: "authenticated" as const,
    evidence,
    stepUps: [],
    startedAt: now - 1,
    lastSeenAt: now,
  })

  it("drops evidence exactly the AAL2 absolute limit old, and keeps it a millisecond younger", () => {
    const now = T0 + policy.timeouts.aal2AbsoluteMs
    expect(policy.assurance(session([password({ at: T0 })], now), now)?.level).toBeNull()
    expect(policy.assurance(session([password({ at: T0 + 1 })], now), now)?.level).toBe("AAL1")
  })

  it("asks for phishing resistance a password and TOTP lack, and for multi-factor proof once it is stale", () => {
    const twoFactor = [password(), totp()]
    expect(policy.require(session(twoFactor, T0), "keys.rotate", T0)).toMatchObject({
      outcome: "step-up",
      missing: [{ kind: "phishing-resistance" }],
    })
    const fresh = policy.require(session(twoFactor, T0 + 999), "billing.pay", T0 + 999)
    expect([fresh.outcome, "missing" in fresh]).toEqual(["allow", false])
    expect(policy.require(session(twoFactor, T0 + 1_000), "billing.pay", T0 + 1_000)).toMatchObject(
      {
        outcome: "step-up",
        missing: [{ kind: "fresh-multi-factor", withinMs: 1_000 }],
      },
    )
  })

  it("starts an enrolling session with no step-ups", async () => {
    const { sessions } = setup()
    const issued = await sessions.begin(TENANT, null, { subject: "acct-1", state: "pre-auth" })
    expect((await sessions.read(TENANT, issued.token))?.state.stepUps).toEqual([])
  })
})

describe("HOTP, cookies and the memory store's arguments", () => {
  it("encodes a counter past 2^32 in its high word, and refuses a digit count outside 6 to 8", async () => {
    expect(await hotp(RFC_KEY, 0, 6)).toBe("755224")
    // Computed with node:crypto's HMAC-SHA-1 over the big-endian counter 0x0000000100000000.
    expect(await hotp(RFC_KEY, 2 ** 32, 6)).toBe("999456")
    for (const digits of [5, 9]) {
      await expect(hotp(RFC_KEY, 0, digits), String(digits)).rejects.toThrow(
        new RangeError("An HOTP code has 6, 7 or 8 digits."),
      )
    }
  })

  it("refuses a cookie value RFC 6265 does not allow", () => {
    expect(() =>
      serializeCookie("__Host-test-cap", "a b", { httpOnly: true, sameSite: "Lax" }),
    ).toThrow(new TypeError("The cookie value has characters RFC 6265 does not allow."))
  })

  it("names each bad argument of increment and revokeByOwner", async () => {
    const store = memoryStore()
    await expect(store.increment("", "c", 1, 0)).rejects.toThrow(
      new TypeError("The tenant must be a non-empty string."),
    )
    await expect(store.increment(TENANT, "", 1, 0)).rejects.toThrow(
      new TypeError("The counter must be a non-empty string."),
    )
    await expect(store.increment(TENANT, "c", 0, 0)).rejects.toThrow(
      new RangeError("The window must be a whole number of at least 1."),
    )
    await expect(store.increment(TENANT, "c", 1, -1)).rejects.toThrow(
      new RangeError("The time must be a whole number of at least 0."),
    )
    await expect(store.revokeByOwner(TENANT, "c", "o", -1)).rejects.toThrow(
      new RangeError("The revocation time must be a whole number of at least 0."),
    )
  })
})

describe("the HIBP timer and the client-address default", () => {
  it("clears the HIBP timer once the range answers", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] })
    try {
      const answer = await screenWithHibp(normalisePassword("password"), () =>
        Promise.resolve({
          ok: true,
          status: 200,
          text: () => Promise.resolve("0018A45C4D1DEF81644B54AB7F969B88D65:2"),
        }),
      )
      expect(answer).toBe("clear")
      expect(vi.getTimerCount()).toBe(0)
    } finally {
      vi.useRealTimers()
    }
  })

  it("needs requireClientAddress to be true or false, and requires an address by default in production", () => {
    const problems = (config: Record<string, unknown>, env: Record<string, string>) => {
      try {
        createAuth({
          store: { ...memoryStore(), kind: "sql", durable: true },
          env,
          hibpFetch: hibpClear,
          sendEmail: discardEmail,
          ...config,
        })
        return []
      } catch (error) {
        if (error instanceof ConfigError) return error.problems
        throw error
      }
    }
    expect(problems({ requireClientAddress: "yes" }, ENV)).toEqual([
      "requireClientAddress must be true or false.",
    ])
    const production = {
      APP_ENV: "production",
      APP_SYSTEM_ID: "billing-web",
      APP_ORIGIN: ORIGIN,
      AUTH_ENCRYPTION_KEY: keyRing("e1", 3),
      AUTH_CSRF_KEY: keyRing("c1", 5),
    }
    const auth = createAuth({
      store: { ...memoryStore(), kind: "sql", durable: true },
      env: production,
      hibpFetch: hibpClear,
      sendEmail: discardEmail,
    })
    expect(() => fetchAuth(auth)).toThrow(ConfigError)
  })
})

describe("the memory store, the store port and the limit store, operation by operation", () => {
  it("passes the store conformance suite, and names each bad argument of resetCounter, revoke and consumeOnce", async () => {
    expect((await runAuthStoreConformance(() => memoryStore())).passed).toBe(true)
    const store = memoryStore()
    await expect(store.resetCounter("", "c")).rejects.toThrow(
      new TypeError("The tenant must be a non-empty string."),
    )
    await expect(store.resetCounter(TENANT, "")).rejects.toThrow(
      new TypeError("The counter must be a non-empty string."),
    )
    await expect(store.revoke(TENANT, "c", "k", -1)).rejects.toThrow(
      new RangeError("The revocation time must be a whole number of at least 0."),
    )
    await expect(store.consumeOnce(TENANT, "c", "k", -1)).rejects.toThrow(
      new RangeError("The time must be a whole number of at least 0."),
    )
  })

  it("names each bad part of a new record", async () => {
    const store = memoryStore()
    const record = { collection: "c", key: "k", owner: null, data: 1 }
    for (const [bad, error] of [
      [{ key: "" }, new TypeError("The key must be a non-empty string.")],
      [{ owner: "" }, new TypeError("The owner must be a non-empty string.")],
      [{ expiresAt: 1.5 }, new RangeError("expiresAt must be a whole number of at least 0.")],
      [{ data: { a: [1, undefined] } }, new TypeError("data.a[1] is not plain JSON.")],
      [{ data: new Date(0) }, new TypeError("data is not plain JSON.")],
    ] as const) {
      await expect(
        store.createUnique(TENANT, { ...record, ...bad } as never),
        JSON.stringify(bad),
      ).rejects.toThrow(error)
    }
  })

  it("runs atomically in the store's transaction when it has one, and on the store when it has none", async () => {
    const plain = { ...memoryStore() }
    Reflect.deleteProperty(plain, "transaction")
    const inner = memoryStore()
    const transactional = {
      ...memoryStore(),
      transaction: <T>(fn: (ops: StoreOperations) => Promise<T>) => fn(inner),
    }
    const seen: StoreOperations[] = []
    await atomically(plain, (ops) => Promise.resolve(seen.push(ops)))
    await atomically(transactional, (ops) => Promise.resolve(seen.push(ops)))
    expect(seen[0]).toBe(plain)
    expect(seen[1]).toBe(inner)
  })

  it("names the key of every counter and limit-block operation", async () => {
    const inner = memoryStore()
    const named = limitStore(inner, (key) => Promise.resolve(`named:${key}`))
    await named.increment(TENANT, "c", 60_000, 0)
    expect((await inner.increment(TENANT, "named:c", 60_000, 0)).count).toBe(2)
    await named.resetCounter(TENANT, "c")
    expect((await inner.increment(TENANT, "named:c", 60_000, 0)).count).toBe(1)
    await named.createUnique(TENANT, {
      collection: LIMIT_BLOCK_COLLECTION,
      key: "k",
      owner: null,
      data: 1,
    })
    const stored = await named.get(TENANT, LIMIT_BLOCK_COLLECTION, "k")
    expect(stored?.data).toBe(1)
    expect(
      await named.update(TENANT, LIMIT_BLOCK_COLLECTION, "k", stored?.version ?? 0, { data: 2 }),
    ).toBe("updated")
    expect((await inner.get(TENANT, LIMIT_BLOCK_COLLECTION, "named:k"))?.data).toBe(2)
    expect(await named.delete(TENANT, LIMIT_BLOCK_COLLECTION, "k")).toBe(true)
    expect(await inner.get(TENANT, LIMIT_BLOCK_COLLECTION, "named:k")).toBeNull()
  })

  it("holds the failure ceiling once reached, and lifts it on a success", async () => {
    const ceiling = createFailureCeiling({
      store: memoryStore(),
      tenant: TENANT,
      clock: fixedClock(T0),
      limit: 1,
    })
    expect(await ceiling.reached("a")).toBe(false)
    await ceiling.failed("a")
    expect(await ceiling.reached("a")).toBe(true)
    await ceiling.succeeded("a")
    expect(await ceiling.reached("a")).toBe(false)
  })
})

describe("accounts, codes, cookies and headers", () => {
  it("resolves only an active account through a live identifier", async () => {
    const store = memoryStore()
    await store.createUnique(TENANT, {
      collection: ACCOUNT_COLLECTION,
      key: "acct-1",
      owner: "acct-1",
      data: { status: "active" },
    })
    for (const key of ["live", "gone"]) {
      await store.createUnique(TENANT, {
        collection: IDENTIFIER_COLLECTION,
        key,
        owner: "acct-1",
        data: { account: "acct-1" },
      })
    }
    await store.revoke(TENANT, IDENTIFIER_COLLECTION, "gone", T0)
    expect(await resolveConfirmed(store, TENANT, "live")).toBe("acct-1")
    expect(await resolveConfirmed(store, TENANT, "gone")).toBeNull()
    expect(await resolveConfirmed(store, TENANT, "none")).toBeNull()
  })

  it("draws digits by rejection, refusing bytes at and above 250, until it has them all", () => {
    expect(randomDigits(sequenceRandom([250, 255, 4]), 1)).toBe("4")
    expect(randomDigits(sequenceRandom([255, 3, 7]), 2)).toBe("37")
  })

  it("pads an HOTP code with leading zeros", async () => {
    expect(await hotp(RFC_KEY, 30, 6)).toBe("026920")
    expect(await hotp(RFC_KEY, 30, 8)).toBe("04026920")
  })

  it("refuses a bad Max-Age, sets HttpOnly only when asked, and reads a repeated cookie as ambiguous", () => {
    for (const maxAge of [-1, 1.5]) {
      expect(() =>
        serializeCookie("__Host-a", "v", { httpOnly: true, sameSite: "Lax", maxAge }),
      ).toThrow(new RangeError("Max-Age must be a non-negative whole number of seconds."))
    }
    expect(serializeCookie("__Host-a", "v", { httpOnly: false, sameSite: "Lax", maxAge: 0 })).toBe(
      "__Host-a=v; Path=/; Max-Age=0; Secure; SameSite=Lax",
    )
    expect(readCookie(new Headers([["cookie", "__Host-a=1; __Host-a=2"]]), "__Host-a")).toEqual({
      kind: "ambiguous",
    })
  })

  it("refuses a single-valued header sent twice", () => {
    expect(singleHeader(new Headers([["origin", "https://a.example"]]), "origin")).toBe(
      "https://a.example",
    )
    expect(() =>
      singleHeader(new Headers([["origin", "https://a.example, https://b.example"]]), "origin"),
    ).toThrow(new TransportError("ambiguous-header", "The origin header was sent more than once."))
  })
})

describe("the policy's outcomes", () => {
  const policy = defineAuthPolicy({
    version: "1",
    requirements: {
      "billing.pay": { level: "AAL2" },
      "keys.rotate": { level: "AAL2", phishingResistantWithinMs: 1_000 },
    },
  })
  const base = { subject: "acct-1", stepUps: [], startedAt: T0, lastSeenAt: T0 }

  it("answers recovery-only, unauthenticated with no level, and a missing level", () => {
    const recovery = { ...base, state: "recovery-only" as const, evidence: [password()] }
    expect(policy.require(recovery, "billing.pay", T0)).toEqual({ outcome: "recovery-only" })
    const bare = { ...base, state: "authenticated" as const, evidence: [] }
    expect(policy.require(bare, "billing.pay", T0)).toEqual({ outcome: "unauthenticated" })
    const single = { ...base, state: "authenticated" as const, evidence: [password()] }
    expect(policy.require(single, "billing.pay", T0)).toMatchObject({
      outcome: "step-up",
      missing: [{ kind: "level", level: "AAL2" }],
    })
  })

  it("asks again for phishing-resistant proof once it is stale, and dates multi-factor proof by its newest suffix", () => {
    const keyed = { ...base, state: "authenticated" as const, evidence: [hardwareKey()] }
    expect(policy.require(keyed, "keys.rotate", T0 + 999)).toMatchObject({ outcome: "allow" })
    expect(policy.require(keyed, "keys.rotate", T0 + 1_000)).toMatchObject({
      outcome: "step-up",
      missing: [{ kind: "fresh-phishing-resistance", withinMs: 1_000 }],
    })
    const evidence = [password({ at: T0 }), totp({ at: T0 + 10 }), password({ at: T0 + 20 })]
    const signedIn = { ...base, state: "authenticated" as const, evidence, lastSeenAt: T0 + 20 }
    expect(policy.assurance(signedIn, T0 + 20)?.lastMultiFactorAt).toBe(T0 + 10)
  })
})

describe("paths, TOTP steps, base32 and page assets", () => {
  it("reads the raw path of an origin-form or absolute URL, and refuses a scheme-relative one", () => {
    expect(rawPath("/auth/x?y=1")).toBe("/auth/x")
    expect(rawPath("/auth/x#f")).toBe("/auth/x")
    expect(rawPath("/a//")).toBe("/a//")
    expect(rawPath("https://a.example")).toBe("/")
    expect(rawPath("https://a.example/auth/x?y")).toBe("/auth/x")
    expect(() => rawPath("//evil.example/auth")).toThrow(
      new TransportError("invalid-path", "The request URL is not absolute or origin-form."),
    )
  })

  it("matches the auth base path, and refuses every ambiguous path with its reason", () => {
    expect(matchAuthPath("/")).toEqual({ kind: "outside" })
    expect(matchAuthPath("/auth")).toEqual({ kind: "route", segments: [] })
    expect(matchAuthPath("/auth/sign-in")).toEqual({ kind: "route", segments: ["sign-in"] })
    expect(matchAuthPath("/authx")).toEqual({ kind: "outside" })
    expect(matchAuthPath("/other/%41")).toEqual({ kind: "outside" })
    const unsafe =
      "The path has a backslash, whitespace, a control character or an encoded separator."
    const dots = "The path has an empty or dot segment."
    for (const [path, reason] of [
      ["/auth/a%2fb", unsafe],
      ["/auth/a\\b", unsafe],
      ["/auth//x", dots],
      ["/auth/./x", dots],
      ["/auth/../x", dots],
      ["/auth/%41", "Paths under the auth base path are never percent-encoded."],
    ] as const) {
      expect(() => matchAuthPath(path), path).toThrow(new TransportError("invalid-path", reason))
    }
    expect(() => matchAuthPath("/auth", "auth")).toThrow(
      new TypeError("The base path must be a clean absolute path such as /auth."),
    )
  })

  it("finds a TOTP code at step 0, skips steps before it, and refuses a step already used", async () => {
    expect(await findStep(RFC_KEY, "755224", 0, null)).toBe(0)
    expect(await findStep(RFC_KEY, "755224", 0, 0)).toBeNull()
    expect(await findStep(RFC_KEY, "000000", 0, null)).toBeNull()
  })

  it("encodes base32 by RFC 4648, padding the last group with zero bits", () => {
    const encode = (text: string) => base32Encode(new TextEncoder().encode(text))
    expect([encode("f"), encode("fo"), encode("foobar")]).toEqual(["MY", "MZXQ", "MZXW6YTBOI"])
  })

  it("names each page asset by the first 12 hex characters of its SHA-256, under a directory base", async () => {
    const short = (text: string) => createHash("sha256").update(text).digest("hex").slice(0, 12)
    const assets = await pageAssets()
    expect([assets.script.path, assets.script.contentType]).toEqual([
      `/auth/assets/test-cap.${short(CLIENT_SCRIPT)}.js`,
      "text/javascript; charset=utf-8",
    ])
    expect([assets.style.path, assets.style.contentType]).toEqual([
      `/auth/assets/test-cap.${short(STYLESHEET)}.css`,
      "text/css; charset=utf-8",
    ])
    await expect(pageAssets("assets/")).rejects.toThrow(
      new TypeError(
        "The asset base must be a directory path on this origin, such as /auth/assets/.",
      ),
    )
  })
})
