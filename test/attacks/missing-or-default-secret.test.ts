// Attack: production runs with a key that is missing, empty, too short, or copied from documentation, so tokens and
// encrypted secrets are forgeable by anyone who read the same example.
// Stopped by: both layers refuse it. env-cap's validation fails startup naming the variable (never the value), and
// createAuth's readiness check refuses it too, for apps that pass plain values (ADR 0022, ADR 0026).
import { EnvValidationError, resetEnvCache, validateEnv } from "@maverickcer/env-cap"
import { readFileSync } from "node:fs"
import path from "node:path"
import { afterEach, describe, expect, it, vi } from "vitest"

// Capture what env.schema.ts hands to documentEnv when it loads, so the declarations are checked as values, not as
// source text. Everything else in env-cap stays real.
const documented = vi.hoisted(() => [] as { variables: Record<string, { sensitivity?: string }> }[])
vi.mock("@maverickcer/env-cap", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@maverickcer/env-cap")>()
  return {
    ...actual,
    documentEnv: (
      schema: unknown,
      docs: { variables: Record<string, { sensitivity?: string }> },
    ) => {
      documented.push(docs)
      actual.documentEnv(schema as never, docs as never)
    },
  }
})
import { base64UrlEncode } from "../../src/core/encoding.js"
import { checkReadiness } from "../../src/core/mode.js"
import { testCapAuditEnv, testCapEnv } from "../../src/env.schema.js"

const random = (seed: number): string =>
  `k1:${base64UrlEncode(Uint8Array.from({ length: 32 }, (_, i) => (i * 73 + seed) % 256))}`

const WEAK: Record<string, string> = {
  empty: "",
  "no key id": base64UrlEncode(new Uint8Array(32).fill(7)),
  "16 bytes": `k1:${base64UrlEncode(Uint8Array.from({ length: 16 }, (_, i) => i * 11))}`,
  "one repeated byte": `k1:${base64UrlEncode(new Uint8Array(32).fill(0x41))}`,
  "all zero": `k1:${base64UrlEncode(new Uint8Array(32))}`,
  "counting bytes": `k1:${base64UrlEncode(Uint8Array.from({ length: 32 }, (_, i) => i))}`,
  "short repeating phrase": `k1:${base64UrlEncode(new TextEncoder().encode("changeme".repeat(4)))}`,
}

const base = {
  APP_ORIGIN: "https://app.example",
  APP_SYSTEM_ID: "billing-web",
  APP_ENV: "production",
  AUTH_ENCRYPTION_KEY: random(1),
  AUTH_CSRF_KEY: random(2),
}

afterEach(() => resetEnvCache())

describe("missing-or-default-secret", () => {
  for (const [label, value] of Object.entries(WEAK)) {
    it(`refuses a ${label} key at env validation, naming the variable and not the value`, async () => {
      let error: unknown
      try {
        await validateEnv({ values: { ...base, AUTH_CSRF_KEY: value }, manifest: [testCapEnv] })
      } catch (caught) {
        error = caught
      }
      expect(error).toBeInstanceOf(EnvValidationError)
      expect((error as Error).message).toContain("AUTH_CSRF_KEY")
      if (value.length > 3) expect((error as Error).message).not.toContain(value.slice(3, 20))
    })

    it(`refuses a ${label} key at startup without env-cap`, () => {
      const problems = checkReadiness({
        mode: "production",
        origin: "https://app.example",
        store: { kind: "sql", durable: true },
        secrets: { AUTH_CSRF_KEY: value },
      })
      expect(problems).toHaveLength(1)
      expect(problems[0]).toMatch(/^AUTH_CSRF_KEY /)
    })
  }

  it("refuses a missing key in production at both layers", async () => {
    const withoutKey = { ...base, AUTH_CSRF_KEY: undefined }
    await expect(validateEnv({ values: withoutKey, manifest: [testCapEnv] })).rejects.toThrow(
      /AUTH_CSRF_KEY/,
    )
    expect(
      checkReadiness({
        mode: "production",
        origin: "https://app.example",
        store: { kind: "sql", durable: true },
        secrets: { AUTH_CSRF_KEY: undefined },
      }),
    ).toEqual(["AUTH_CSRF_KEY is missing."])
  })

  it("refuses missing audit keys once the app turns the audit trail on", async () => {
    await expect(
      validateEnv({
        values: base,
        manifest: [testCapEnv, testCapAuditEnv],
        activeContexts: ["test-cap-audit"],
      }),
    ).rejects.toThrow(/AUTH_AUDIT_KEY is missing\./)
  })

  it("accepts real random keys", async () => {
    await expect(validateEnv({ values: base, manifest: [testCapEnv] })).resolves.toBeDefined()
  })
})

describe("missing-or-default-secret: the keys the examples commit", () => {
  // Each example ships a committed .env for local development (examples/<name>/.env). Its keys are public, so
  // production and staging refuse them at both layers; development and test accept them, so the examples run.
  const examples = ["nextjs", "tanstack-start"].map((name) => {
    const text = readFileSync(
      path.resolve(import.meta.dirname, "../../examples", name, ".env"),
      "utf8",
    )
    const values = Object.fromEntries(
      text
        .split("\n")
        .filter((line) => /^[A-Z_]+=/.test(line))
        .map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]),
    )
    return { name, text, values }
  })

  it.each(examples)(
    "$name: says on its first line that the values are for local development only",
    ({ text, values }) => {
      expect(text.split("\n")[0]).toBe(
        "# These values work for local development only. Never use them in production: they are public, and production refuses these keys.",
      )
      expect(values).toMatchObject({ APP_ENV: "development", APP_ORIGIN: "http://localhost:3000" })
      expect(Object.keys(values).sort()).toEqual([
        "APP_ENV",
        "APP_ORIGIN",
        "APP_SYSTEM_ID",
        "AUTH_CSRF_KEY",
        "AUTH_ENCRYPTION_KEY",
      ])
    },
  )

  it.each(examples)(
    "$name: its keys are refused in production and staging, naming each",
    async ({ values }) => {
      for (const mode of ["production", "staging"] as const) {
        expect(
          checkReadiness({
            mode,
            origin: "https://app.example",
            store: { kind: "sql", durable: true },
            secrets: {
              AUTH_ENCRYPTION_KEY: values["AUTH_ENCRYPTION_KEY"],
              AUTH_CSRF_KEY: values["AUTH_CSRF_KEY"],
            },
          }),
        ).toEqual([
          "AUTH_ENCRYPTION_KEY entry 1 is a published example key; generate a new one.",
          "AUTH_CSRF_KEY entry 1 is a published example key; generate a new one.",
        ])
      }
      // Behind a fresh key it is still refused, wherever it sits in the ring.
      const ring = `${random(9).replace("k1", "k2")},${values["AUTH_CSRF_KEY"] as string}`
      expect(
        checkReadiness({
          mode: "production",
          origin: "https://app.example",
          store: { kind: "sql", durable: true },
          secrets: { AUTH_CSRF_KEY: ring },
        }),
      ).toEqual(["AUTH_CSRF_KEY entry 2 is a published example key; generate a new one."])
      await expect(
        validateEnv({
          values: { ...base, AUTH_CSRF_KEY: values["AUTH_CSRF_KEY"] },
          manifest: [testCapEnv],
        }),
      ).rejects.toThrow(/AUTH_CSRF_KEY/)
    },
  )

  it.each(examples)("$name: its keys are accepted in development and test", async ({ values }) => {
    for (const mode of ["development", "test"] as const) {
      expect(
        checkReadiness({
          mode,
          origin: "http://localhost:3000",
          store: { kind: "memory", durable: false },
          secrets: {
            AUTH_ENCRYPTION_KEY: values["AUTH_ENCRYPTION_KEY"],
            AUTH_CSRF_KEY: values["AUTH_CSRF_KEY"],
          },
        }),
      ).toEqual([])
    }
    await expect(
      validateEnv({ values: { ...values, APP_ENV: "development" }, manifest: [testCapEnv] }),
    ).resolves.toBeDefined()
  })
})

describe("missing-or-default-secret: every key is declared secret", () => {
  // env-cap redacts and reports a variable by its declared sensitivity, so a key documented without
  // `sensitivity: "secret"` could reach a log or an evidence file. Every documented AUTH_ variable that holds key
  // material must say so. The certificate is public and is the one exception.
  const variables = new Map(documented.flatMap(({ variables: entries }) => Object.entries(entries)))

  it("documents every AUTH_ variable the contracts read", () => {
    expect([...variables.keys()].filter((name) => name.startsWith("AUTH_")).sort()).toEqual([
      "AUTH_AUDIT_KEY",
      "AUTH_AUDIT_SIGNING_KEY",
      "AUTH_CSRF_KEY",
      "AUTH_ENCRYPTION_KEY",
      "AUTH_SAML_SP_CERT",
      "AUTH_SAML_SP_PRIVATE_KEY",
    ])
  })

  it.each([
    "AUTH_AUDIT_KEY",
    "AUTH_AUDIT_SIGNING_KEY",
    "AUTH_CSRF_KEY",
    "AUTH_ENCRYPTION_KEY",
    "AUTH_SAML_SP_PRIVATE_KEY",
  ])("%s is declared secret", (name) => {
    expect(variables.get(name)?.sensitivity).toBe("secret")
  })

  it("leaves the public certificate undeclared", () => {
    expect(variables.get("AUTH_SAML_SP_CERT")?.sensitivity).toBeUndefined()
  })
})
