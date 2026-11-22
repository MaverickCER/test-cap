// Attack: a store, library or hook error makes `require` answer `allow`.
// Stopped by: errors map to `unauthenticated` or a 5xx; no error path yields `allow` (ADR 0003, 0005).
import { describe, expect, it } from "vitest"
import { memoryStore } from "../../src/store/memory.js"
import type { AuthStore } from "../../src/store/port.js"
import { password, totp } from "../support/evidence.js"
import { setup, TENANT } from "../support/sessions.js"

describe("fail-open-on-error", () => {
  it("rejects, never allows, when the store fails to read or to record activity", async () => {
    for (const failing of ["get", "update"] as const) {
      const memory = memoryStore()
      let broken = false
      const store: AuthStore = {
        ...memory,
        [failing]: (...args: Parameters<AuthStore[typeof failing]>) => {
          if (broken) return Promise.reject(new Error("store down"))
          return (memory[failing] as (...a: typeof args) => Promise<unknown>)(...args)
        },
      } as AuthStore
      const { sessions } = setup({ store })
      const issued = await sessions.signIn(TENANT, null, {
        subject: "acct-1",
        evidence: [password(), totp()],
      })
      broken = true
      await expect(sessions.require(TENANT, issued.token, "default"), failing).rejects.toThrow(
        "store down",
      )
    }
  })

  it("throws on an unknown requirement id instead of falling back to a weaker one", async () => {
    const { sessions } = setup()
    const issued = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password(), totp()],
    })
    // @ts-expect-error -- an unknown requirement id is a type error; at run time it fails closed
    await expect(sessions.require(TENANT, issued.token, "billing.delete")).rejects.toThrow(
      'Unknown requirement id "billing.delete".',
    )
  })
})
