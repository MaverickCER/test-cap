/**
 * What one successful ceremony proves, recorded as data (ADR 0005 §1). Methods produce `AuthenticationEvidence`;
 * the assurance model computes a session's level from the evidence still valid and never from a stored level.
 */

/** A NIST SP 800-63B-4 authenticator assurance level. */
export type AssuranceLevel = "AAL1" | "AAL2" | "AAL3"

/** How the key behind a possession factor is held: `non-exportable` is required for AAL3 (ADR 0005 §3). */
export type KeyProtection = "non-exportable" | "syncable" | "unknown"

/** The methods that produce evidence. Email sign-in and recovery codes produce none (ADR 0005 §5, ADR 0007). */
export type AuthenticationMethod =
  "password" | "totp" | "passkey" | "recovery-code" | "oidc" | "saml"

/** The kinds of proof an authenticator gives. */
export type Factor = "knowledge" | "possession" | "inherence"

/** What one successful ceremony proves. A failed ceremony produces none. */
export interface AuthenticationEvidence {
  /** The method whose ceremony produced this evidence. */
  readonly method: AuthenticationMethod
  /** The id of the authenticator used, so its own expiry and failure counters can be found. */
  readonly authenticatorId: string
  /** The factors this one ceremony proved; a passkey with user verification proves two. */
  readonly factors: readonly Factor[]
  /** True when the ceremony is bound to the origin, so a phishing site cannot relay it. */
  readonly phishingResistant: boolean
  /** True when a captured response cannot be used again. */
  readonly replayResistant: boolean
  /** How the key behind a possession factor is held; `unknown` for knowledge factors and federation. */
  readonly keyProtection: KeyProtection
  /** Whether the authenticator verified the person (PIN or biometric) during this ceremony. */
  readonly userVerified: boolean
  /** Whether attestation was verified to a trusted root during registration. */
  readonly attestationVerified: boolean
  /** When the ceremony completed, in milliseconds since the epoch, from the injected clock. */
  readonly at: number
  /** For federation only: the issuer and the upstream authentication context it reported. */
  readonly federation?: {
    /** The issuer that authenticated the person, as listed in the trust config. */
    readonly issuer: string
    /** The authentication context class the issuer reported, or `null` when it sent none. */
    readonly acr: string | null
    /** The authentication methods the issuer reported, as sent. */
    readonly amr: readonly string[]
    /**
     * When the person authenticated at the issuer (OIDC `auth_time`, SAML `AuthnInstant`), in milliseconds since the
     * epoch. A trusted issuer's maximum authentication age runs from it, never from `at`.
     */
    readonly authTime: number
  }
}
