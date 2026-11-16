/**
 * test-cap's environment contracts (ADR 0022). env-cap discovers this file through `"envCap": { "schema" }` in
 * package.json (env-cap ADR 0014), so an app that lists `test-cap` in its `packages` gets these variables documented
 * and validated with its own.
 *
 * Three contracts, so an app is only asked for what it turns on: the core (always), audit, and SAML. APP_ORIGIN,
 * APP_SYSTEM_ID and APP_ENV are declared identically by every cap; env-cap reports any drift between them as
 * `DUPLICATE_VARIABLE_DOCUMENTATION` (env-cap ADR 0050). Each key's expiry belongs to the app's copy of the key, so the
 * app adds `expiresAt` in its own declaration and env-cap merges it with this one.
 */

import { createEnv, documentEnv } from "@maverickcer/env-cap"
import { originProblem, resolveDeploymentMode } from "./core/mode.js"
import {
  appEnvProblem,
  keyRingVariableProblem,
  pemProblem,
  systemIdProblem,
} from "./env/validators.js"

const text = (value: unknown): string => (typeof value === "string" ? value : "")

const testCapSchema = {
  APP_ORIGIN: {
    processor: text,
    validator: (value: string, raw: Readonly<Record<string, unknown>>) =>
      originProblem(value, resolveDeploymentMode(text(raw["APP_ENV"])).mode) ?? true,
  },
  APP_SYSTEM_ID: { processor: text, validator: (value: string) => systemIdProblem(value) },
  APP_ENV: { processor: text, validator: (value: string) => appEnvProblem(value) },
  AUTH_ENCRYPTION_KEY: {
    processor: text,
    validator: (value: string, raw: Readonly<Record<string, unknown>>) =>
      keyRingVariableProblem("AUTH_ENCRYPTION_KEY", value, raw),
  },
  AUTH_CSRF_KEY: {
    processor: text,
    validator: (value: string, raw: Readonly<Record<string, unknown>>) =>
      keyRingVariableProblem("AUTH_CSRF_KEY", value, raw),
  },
}

/** The core contract: the shared variables and the two keys every deployment needs. */
export const testCapEnv = createEnv(testCapSchema, { name: "test-cap", source: import.meta.url })

documentEnv(testCapSchema, {
  owner: "test-cap",
  category: "authentication",
  variables: {
    APP_ORIGIN: {
      description:
        "Where the app is served, as a bare origin (https://app.example). Requests that change state must come from it, and every emailed link is built from it.",
      required: true,
      setupInstructions:
        "Set to the public https origin. development and test also accept http on localhost.",
    },
    APP_SYSTEM_ID: {
      description:
        "Names this system in security events and audit records, so one log can serve several apps.",
      required: true,
      setupInstructions:
        "Choose a short, stable id such as billing-web; never reuse one across systems.",
    },
    APP_ENV: {
      description:
        "The deployment mode: production, staging, development or test. Without env-cap, a missing or unknown value runs as production.",
      required: true,
      setupInstructions:
        "Set explicitly in every environment; staging gets the same checks as production.",
    },
    AUTH_ENCRYPTION_KEY: {
      description:
        "Encrypts TOTP secrets at rest (AES-GCM). A key ring: id:base64url entries, the first one current.",
      sensitivity: "secret",
      required: true,
      rotationPeriod: "P90D",
      setupInstructions: "Generate 32 random bytes, base64url-encode them, and set k1:<value>.",
      refreshInstructions:
        "Put a new id:key first and keep the old entry after it until every secret is re-encrypted, then remove it.",
    },
    AUTH_CSRF_KEY: {
      description:
        "Signs the synchronizer tokens on state-changing requests. A key ring like AUTH_ENCRYPTION_KEY.",
      sensitivity: "secret",
      required: true,
      rotationPeriod: "P90D",
      setupInstructions: "Generate 32 random bytes, base64url-encode them, and set k1:<value>.",
      refreshInstructions:
        "Put a new id:key first and keep the old one until open forms have expired, then remove it.",
    },
  },
})

const testCapAuditSchema = {
  AUTH_AUDIT_KEY: {
    processor: text,
    validator: (value: string, raw: Readonly<Record<string, unknown>>) =>
      keyRingVariableProblem("AUTH_AUDIT_KEY", value, raw),
  },
  AUTH_AUDIT_SIGNING_KEY: {
    processor: text,
    validator: (value: string, raw: Readonly<Record<string, unknown>>) =>
      keyRingVariableProblem("AUTH_AUDIT_SIGNING_KEY", value, raw),
  },
}

/** The audit contract: needed only when the audit trail is on. */
export const testCapAuditEnv = createEnv(testCapAuditSchema, {
  name: "test-cap-audit",
  source: import.meta.url,
})

documentEnv(testCapAuditSchema, {
  owner: "test-cap",
  category: "audit",
  variables: {
    AUTH_AUDIT_KEY: {
      description:
        "Links each audit record to the one before it (HMAC-SHA-256). A key ring with key ids.",
      sensitivity: "secret",
      required: true,
      rotationPeriod: "P365D",
      setupInstructions:
        "Generate 32 random bytes, base64url-encode them, and set k1:<value>. Keep it out of the database.",
      refreshInstructions:
        "Put a new id:key first; keep old ids for as long as records signed with them are retained.",
    },
    AUTH_AUDIT_SIGNING_KEY: {
      description:
        "Signs audit checkpoints with Ed25519, so anyone holding the public key can verify them.",
      sensitivity: "secret",
      required: true,
      rotationPeriod: "P365D",
      setupInstructions:
        "Generate an Ed25519 key pair; store the private key here and publish the public key.",
      refreshInstructions:
        "Put a new id:key first and publish its public key; old checkpoints stay verifiable.",
    },
  },
})

const testCapSamlSchema = {
  AUTH_SAML_SP_PRIVATE_KEY: {
    processor: text,
    validator: (value: string, raw: Readonly<Record<string, unknown>>) =>
      pemProblem("AUTH_SAML_SP_PRIVATE_KEY", "PRIVATE KEY", value, raw),
  },
  AUTH_SAML_SP_CERT: {
    processor: text,
    validator: (value: string, raw: Readonly<Record<string, unknown>>) =>
      pemProblem("AUTH_SAML_SP_CERT", "CERTIFICATE", value, raw),
  },
}

/** The SAML contract: needed only when SAML is on. */
export const testCapSamlEnv = createEnv(testCapSamlSchema, {
  name: "test-cap-saml",
  source: import.meta.url,
})

documentEnv(testCapSamlSchema, {
  owner: "test-cap",
  category: "authentication",
  variables: {
    AUTH_SAML_SP_PRIVATE_KEY: {
      description: "The SAML service provider's signing key, as one PKCS#8 PEM block.",
      sensitivity: "secret",
      required: true,
      setupInstructions:
        "Generate a key pair for this service provider only; never reuse a TLS key.",
      refreshInstructions:
        "Publish new metadata with the new certificate first, then switch the key.",
    },
    AUTH_SAML_SP_CERT: {
      description:
        "The certificate for the SAML signing key, published in this service provider's metadata.",
      required: true,
      setupInstructions: "Self-signed is fine; identity providers trust it through the metadata.",
      refreshInstructions:
        "Set the app's expiresAt to the certificate's notAfter, and rotate before it.",
    },
  },
})
