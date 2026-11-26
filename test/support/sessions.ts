import { ACCOUNT_COLLECTION } from "../../src/core/accounts.js"
import type { AuthenticationEvidence } from "../../src/assurance/evidence.js"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import {
  fixedClock,
  sequenceRandom,
  systemRandom,
  type RandomSource,
} from "../../src/core/clock.js"
import { createSessions } from "../../src/sessions/sessions.js"
import { memoryStore } from "../../src/store/memory.js"
import type { AuthStore } from "../../src/store/port.js"
import { T0 } from "./evidence.js"

export const TENANT = "t1"

export const policy = defineAuthPolicy({
  version: "1",
  requirements: {
    "profile.read": { level: "AAL1" },
    "keys.rotate": { level: "AAL2", phishingResistant: true },
    "admin.root": { level: "AAL3" },
  },
})

/** A session manager over a fresh memory store and a clock fixed at T0. */
export function setup(options: { store?: AuthStore; random?: RandomSource } = {}) {
  const store = options.store ?? memoryStore()
  const clock = fixedClock(T0)
  const base = createSessions({ store, clock, random: options.random ?? systemRandom, policy })
  // A session counts only for an active account (ADR 0012), so each subject gets one the first time it signs in.
  const active = async (tenant: string, subject: string): Promise<void> => {
    await store.createUnique(tenant, {
      collection: ACCOUNT_COLLECTION,
      key: subject,
      owner: subject,
      data: { status: "active", createdAt: T0 },
    })
  }
  const sessions: typeof base = {
    ...base,
    async signIn(tenant, token, input) {
      await active(tenant, input.subject)
      return base.signIn(tenant, token, input)
    },
    async begin(tenant, token, input) {
      await active(tenant, input.subject)
      return base.begin(tenant, token, input)
    },
  }
  return { store, clock, sessions }
}

export { sequenceRandom }

/** Asks for a step-up challenge on the session behind `token` and completes it with `evidence`. */
export async function stepUp(
  sessions: ReturnType<typeof setup>["sessions"],
  token: string,
  evidence: AuthenticationEvidence,
) {
  const challenge = await sessions.beginStepUp(TENANT, token)
  return sessions.stepUp(TENANT, token, challenge ?? "", evidence)
}
