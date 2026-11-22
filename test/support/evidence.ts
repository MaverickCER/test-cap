import type { AuthenticationEvidence } from "../../src/assurance/evidence.js"

/** The epoch the assurance and session tests start from. */
export const T0 = 1_800_000_000_000
export const MINUTE = 60_000
export const HOUR = 60 * MINUTE

const base: AuthenticationEvidence = {
  method: "password",
  authenticatorId: "pw-1",
  factors: ["knowledge"],
  phishingResistant: false,
  replayResistant: false,
  keyProtection: "unknown",
  userVerified: false,
  attestationVerified: false,
  at: T0,
}

/** Password evidence: one knowledge factor. */
export function password(overrides: Partial<AuthenticationEvidence> = {}): AuthenticationEvidence {
  return { ...base, ...overrides }
}

/** TOTP evidence: one possession factor, replay-resistant once the time step is stored. */
export function totp(overrides: Partial<AuthenticationEvidence> = {}): AuthenticationEvidence {
  return {
    ...base,
    method: "totp",
    authenticatorId: "totp-1",
    factors: ["possession"],
    replayResistant: true,
    ...overrides,
  }
}

/** A synced passkey with user verification: two factors, phishing-resistant, backup-eligible. */
export function passkey(overrides: Partial<AuthenticationEvidence> = {}): AuthenticationEvidence {
  return {
    ...base,
    method: "passkey",
    authenticatorId: "pk-1",
    factors: ["possession", "inherence"],
    phishingResistant: true,
    replayResistant: true,
    keyProtection: "syncable",
    userVerified: true,
    ...overrides,
  }
}

/** A passkey meeting every AAL3 condition: non-exportable, attested, user-verified, phishing-resistant. */
export function hardwareKey(
  overrides: Partial<AuthenticationEvidence> = {},
): AuthenticationEvidence {
  return passkey({
    authenticatorId: "hk-1",
    keyProtection: "non-exportable",
    attestationVerified: true,
    ...overrides,
  })
}

/** OIDC evidence from `issuer` reporting `acr` and `amr`. */
export function oidc(
  issuer: string,
  acr: string | null,
  amr: readonly string[] = [],
  overrides: Partial<AuthenticationEvidence> = {},
): AuthenticationEvidence {
  return {
    ...base,
    method: "oidc",
    authenticatorId: `oidc:${issuer}`,
    factors: [],
    federation: { issuer, acr, amr, authTime: overrides.at ?? T0 },
    ...overrides,
  }
}

/** Evidence a method outside test-cap's list claims, such as an email link, smuggled in at run time. */
export function foreign(
  method: string,
  overrides: Partial<AuthenticationEvidence> = {},
): AuthenticationEvidence {
  return {
    ...passkey(),
    keyProtection: "non-exportable",
    attestationVerified: true,
    ...overrides,
    method: method as AuthenticationEvidence["method"],
  }
}
