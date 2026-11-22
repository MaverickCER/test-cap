/**
 * TOTP (RFC 6238) over HOTP (ADR 0027, Open 1 and 2): SHA-1, 6 digits, a 30-second step, one step of drift either
 * side, the time read from the injected clock only. A step at or before the last accepted one is refused.
 */

import { constantTimeEqual, utf8Encode } from "../../core/encoding.js"
import { hotp } from "./hotp.js"

/** Digits in a TOTP code. */
export const TOTP_DIGITS = 6
/** The length of one time step. */
export const TOTP_STEP_MS = 30_000
/** Steps of clock drift accepted either side of the current one. */
export const TOTP_DRIFT_STEPS = 1

/** The time step that contains `epochMilliseconds`. */
export function timeStep(epochMilliseconds: number): number {
  return Math.floor(epochMilliseconds / TOTP_STEP_MS)
}

/**
 * The step within the drift window whose code equals `code` (anything but 6 digits never does) and that is later than `lastStep`, or `null`. Every
 * candidate is computed and compared in constant time, so the time taken does not reveal which one matched.
 */
export async function findStep(
  key: Uint8Array,
  code: string,
  now: number,
  lastStep: number | null,
): Promise<number | null> {
  const presented = utf8Encode(code)
  const first = timeStep(now) - TOTP_DRIFT_STEPS
  const steps = Array.from(
    { length: TOTP_DRIFT_STEPS + 1 + TOTP_DRIFT_STEPS },
    (_, index) => first + index,
  )
  let found: number | null = null
  for (const step of steps) {
    if (step < 0) continue
    const expected = utf8Encode(await hotp(key, step, TOTP_DIGITS))
    if (constantTimeEqual(presented, expected) && (lastStep === null || step > lastStep)) {
      found = step
    }
  }
  return found
}
