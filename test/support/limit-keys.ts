// The limits name every counter and block by an HMAC of its key (ADR 0032), so a test that checks which key was counted
// installs this recorder in its file and reads the key back:
//
//   vi.mock("../../src/security/limit-store.js", async (importOriginal) =>
//     (await import("../support/limit-keys.js")).recordingKeyNames(await importOriginal()))
//
// The store still receives only the HMAC names; the recorder only remembers which key each one stood for.
import type * as LimitStore from "../../src/security/limit-store.js"

/** The key behind each name the limits wrote, in the files that install the recorder. */
const keys = new Map<string, string>()

/** The key a stored name stands for, or the name itself when the recorder never saw it. */
export const plainKeyOf = (name: string): string => keys.get(name) ?? name

/** The limit-store module, with `limitKeyName` remembering the key behind every name it gives. */
export function recordingKeyNames(actual: typeof LimitStore): typeof LimitStore {
  return {
    ...actual,
    limitKeyName(ringKey) {
      const name = actual.limitKeyName(ringKey)
      return async (key) => {
        const named = await name(key)
        keys.set(named, key)
        return named
      }
    },
  }
}
