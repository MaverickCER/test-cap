import { EnvValidationError, resetEnvCache, validateEnv } from "@maverickcer/env-cap"
import { afterEach, describe, expect, it } from "vitest"
import { base64UrlEncode } from "../../src/core/encoding.js"
import { testCapAuditEnv, testCapEnv, testCapSamlEnv } from "../../src/env.schema.js"
import {
  appEnvProblem,
  keyRingVariableProblem,
  pemProblem,
  systemIdProblem,
} from "../../src/env/validators.js"

const key = (seed: number): string =>
  `k1:${base64UrlEncode(Uint8Array.from({ length: 32 }, (_, i) => (i * 73 + seed) % 256))}`

const production = {
  APP_ORIGIN: "https://app.example",
  APP_SYSTEM_ID: "billing-web",
  APP_ENV: "production",
  AUTH_ENCRYPTION_KEY: key(1),
  AUTH_CSRF_KEY: key(2),
}

afterEach(() => resetEnvCache())

type Manifest = Parameters<typeof validateEnv>[0]["manifest"]

async function problems(
  values: Record<string, string | undefined>,
  manifest: Manifest = [testCapEnv],
): Promise<string[]> {
  try {
    await validateEnv({ values, manifest })
    return []
  } catch (error) {
    if (!(error instanceof EnvValidationError)) throw error
    return error.message.split("\n").filter((line) => /APP_|AUTH_/.test(line))
  }
}

describe("testCapEnv (the core contract)", () => {
  it("accepts a complete production environment and exposes the values", async () => {
    await validateEnv({ values: production, manifest: [testCapEnv] })
    expect(testCapEnv.APP_ORIGIN).toBe("https://app.example")
    expect(testCapEnv.APP_ENV).toBe("production")
    expect(testCapEnv.AUTH_CSRF_KEY).toBe(production.AUTH_CSRF_KEY)
  })

  it("names every variable that fails, never its value", async () => {
    const found = await problems({
      ...production,
      APP_ORIGIN: "http://app.example",
      AUTH_ENCRYPTION_KEY: undefined,
      AUTH_CSRF_KEY: "k1:c2VjcmV0LXZhbHVl",
    })
    expect(found.join("\n")).toMatch(/APP_ORIGIN/)
    expect(found.join("\n")).toMatch(/AUTH_ENCRYPTION_KEY/)
    expect(found.join("\n")).toMatch(/AUTH_CSRF_KEY/)
    expect(found.join("\n")).not.toContain("c2VjcmV0LXZhbHVl")
  })

  it("refuses an APP_ENV it does not know, rather than silently running as production", async () => {
    expect((await problems({ ...production, APP_ENV: "prod" })).join("\n")).toMatch(/APP_ENV/)
    expect((await problems({ ...production, APP_ENV: undefined })).join("\n")).toMatch(/APP_ENV/)
  })

  it("lets development leave the keys unset, for keys generated at startup", async () => {
    expect(
      await problems({
        APP_ORIGIN: "http://localhost:3000",
        APP_SYSTEM_ID: "dev",
        APP_ENV: "development",
      }),
    ).toEqual([])
  })
})

describe("the variable each validator names", () => {
  it("is the variable it validates, in every contract", async () => {
    const pem = (label: string): string => `-----BEGIN ${label}-----\nAAAA\n-----END ${label}-----`
    const found = await problems(
      {
        ...production,
        AUTH_ENCRYPTION_KEY: "x",
        AUTH_CSRF_KEY: "x",
        AUTH_AUDIT_KEY: "x",
        AUTH_AUDIT_SIGNING_KEY: "x",
        AUTH_SAML_SP_PRIVATE_KEY: pem("CERTIFICATE"),
        AUTH_SAML_SP_CERT: pem("PRIVATE KEY"),
      },
      [testCapEnv, testCapAuditEnv, testCapSamlEnv],
    )
    for (const variable of [
      "AUTH_ENCRYPTION_KEY",
      "AUTH_CSRF_KEY",
      "AUTH_AUDIT_KEY",
      "AUTH_AUDIT_SIGNING_KEY",
    ]) {
      expect(found).toContain(`${variable} entry 1 is not "id:base64url".`)
    }
    expect(found).toContain("AUTH_SAML_SP_PRIVATE_KEY must be one PEM block labelled PRIVATE KEY.")
    expect(found).toContain("AUTH_SAML_SP_CERT must be one PEM block labelled CERTIFICATE.")
  })
})

describe("the capability contracts", () => {
  it("ask for the audit keys only through the audit contract", async () => {
    const values = { ...production, AUTH_AUDIT_KEY: key(3), AUTH_AUDIT_SIGNING_KEY: key(4) }
    await validateEnv({ values, manifest: [testCapEnv, testCapAuditEnv] })
    expect(testCapAuditEnv.AUTH_AUDIT_KEY).toBe(values.AUTH_AUDIT_KEY)
    resetEnvCache()
    expect((await problems(production, [testCapEnv, testCapAuditEnv])).join("\n")).toMatch(
      /AUTH_AUDIT_KEY/,
    )
  })

  it("ask for the SAML key and certificate only through the SAML contract", async () => {
    const pem = (label: string): string => `-----BEGIN ${label}-----\nAAAA\n-----END ${label}-----`
    const values = {
      ...production,
      AUTH_SAML_SP_PRIVATE_KEY: pem("PRIVATE KEY"),
      AUTH_SAML_SP_CERT: pem("CERTIFICATE"),
    }
    await validateEnv({ values, manifest: [testCapEnv, testCapSamlEnv] })
    resetEnvCache()
    expect(
      (
        await problems({ ...values, AUTH_SAML_SP_CERT: pem("PRIVATE KEY") }, [
          testCapEnv,
          testCapSamlEnv,
        ])
      ).join("\n"),
    ).toMatch(/AUTH_SAML_SP_CERT/)
  })
})

describe("validators", () => {
  it("appEnvProblem accepts the four modes only", () => {
    for (const mode of ["production", "staging", "development", "test"])
      expect(appEnvProblem(mode)).toBe(true)
    expect(appEnvProblem("")).toBe("APP_ENV must be production, staging, development or test.")
  })

  it("systemIdProblem accepts a short identifier", () => {
    expect(systemIdProblem("billing-web.v2_eu")).toBe(true)
    for (const bad of ["", "-lead", "has space", "x".repeat(65)]) {
      expect(systemIdProblem(bad)).toBe(
        "APP_SYSTEM_ID must be 1-64 letters, digits, dots, dashes or underscores, starting with a letter or digit.",
      )
    }
    expect(systemIdProblem("x".repeat(64))).toBe(true)
  })

  it("keyRingVariableProblem requires a key outside development and test", () => {
    expect(keyRingVariableProblem("AUTH_CSRF_KEY", "", { APP_ENV: "production" })).toBe(
      "AUTH_CSRF_KEY is missing.",
    )
    expect(keyRingVariableProblem("AUTH_CSRF_KEY", "", { APP_ENV: "staging" })).toBe(
      "AUTH_CSRF_KEY is missing.",
    )
    expect(keyRingVariableProblem("AUTH_CSRF_KEY", "", {})).toBe("AUTH_CSRF_KEY is missing.")
    expect(keyRingVariableProblem("AUTH_CSRF_KEY", "", { APP_ENV: 1 })).toBe(
      "AUTH_CSRF_KEY is missing.",
    )
    expect(keyRingVariableProblem("AUTH_CSRF_KEY", "", { APP_ENV: "test" })).toBe(true)
    expect(keyRingVariableProblem("AUTH_CSRF_KEY", key(9), { APP_ENV: "production" })).toBe(true)
    expect(keyRingVariableProblem("AUTH_CSRF_KEY", "x", { APP_ENV: "test" })).toBe(
      'AUTH_CSRF_KEY entry 1 is not "id:base64url".',
    )
    expect(keyRingVariableProblem("AUTH_CSRF_KEY", "x,y", { APP_ENV: "test" })).toBe(
      'AUTH_CSRF_KEY entry 1 is not "id:base64url". AUTH_CSRF_KEY entry 2 is not "id:base64url".',
    )
  })

  it("pemProblem requires one PEM block of the expected label", () => {
    const block = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    expect(pemProblem("AUTH_SAML_SP_CERT", "CERTIFICATE", block, { APP_ENV: "production" })).toBe(
      true,
    )
    expect(
      pemProblem("AUTH_SAML_SP_CERT", "CERTIFICATE", `  ${block}\n`, { APP_ENV: "production" }),
    ).toBe(true)
    expect(pemProblem("AUTH_SAML_SP_CERT", "CERTIFICATE", "MIIB", { APP_ENV: "production" })).toBe(
      "AUTH_SAML_SP_CERT must be one PEM block labelled CERTIFICATE.",
    )
    expect(pemProblem("AUTH_SAML_SP_CERT", "CERTIFICATE", "", { APP_ENV: "production" })).toBe(
      "AUTH_SAML_SP_CERT is missing.",
    )
    expect(pemProblem("AUTH_SAML_SP_CERT", "CERTIFICATE", "", { APP_ENV: "development" })).toBe(
      true,
    )
  })
})
