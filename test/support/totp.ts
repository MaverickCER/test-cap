import { fixedClock, type FixedClock, type RandomSource } from "../../src/core/clock.js"
import type { RingKey } from "../../src/core/mode.js"
import { hotp } from "../../src/methods/totp/hotp.js"
import {
  base32Decode,
  beginTotpEnrolment,
  confirmTotpEnrolment,
  type TotpDeps,
} from "../../src/methods/totp/method.js"
import { timeStep } from "../../src/methods/totp/totp.js"
import { memoryStore } from "../../src/store/memory.js"

const T0 = 1_700_000_000_000

/** A seeded xorshift32 source: deterministic, without the short cycle of `sequenceRandom`. For tests only. */
function seededRandom(seed: number): RandomSource {
  let state = seed >>> 0 || 1
  return {
    fill(bytes) {
      for (const index of bytes.keys()) {
        state ^= state << 13
        state >>>= 0
        state ^= state >>> 17
        state ^= state << 5
        state >>>= 0
        bytes[index] = state & 0xff
      }
      return bytes
    },
  }
}

/** A ring key made from `seed`. */
export function ringKey(id: string, seed: number): RingKey {
  return { id, bytes: Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + seed) % 256) }
}

/** TOTP dependencies on a fixed clock and a memory store. */
export function totpDeps(overrides: Partial<TotpDeps> = {}): TotpDeps & { clock: FixedClock } {
  return {
    clock: fixedClock(T0),
    random: seededRandom(20_261_116),
    store: memoryStore(),
    keyRing: [ringKey("k1", 1)],
    ...overrides,
  } as TotpDeps & { clock: FixedClock }
}

/** The code of a base32 secret at `ms`. */
export function codeAt(secret: string, ms: number): Promise<string> {
  return hotp(base32Decode(secret), timeStep(ms), 6)
}

/** Enrols and confirms a TOTP authenticator for account `a` in tenant `t`. */
export async function enrol(
  deps: TotpDeps & { clock: FixedClock },
): Promise<{ authenticatorId: string; secret: string }> {
  const begun = await beginTotpEnrolment(deps, { tenant: "t", accountId: "a" })
  const confirmed = await confirmTotpEnrolment(deps, {
    tenant: "t",
    accountId: "a",
    authenticatorId: begun.authenticatorId,
    code: await codeAt(begun.secret, deps.clock.now()),
  })
  if (!confirmed.ok) throw new Error("enrolment did not confirm")
  return begun
}
