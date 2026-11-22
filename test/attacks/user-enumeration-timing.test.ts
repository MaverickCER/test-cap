// Attack: reply timing reveals whether an account exists (or has a password).
// Stopped by: uniform timing: a dummy argon2id verify whenever no stored password hash is verified (ADR 0009).
import { describe, expect, it } from "vitest"
import { Browser, inProcess, PASSWORD, seedAccount, testAuth } from "../support/auth.js"

const median = (values: number[]) =>
  [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)] ?? 0

describe("user-enumeration-timing", () => {
  it("takes as long to refuse a missing account, or one with no password, as a wrong password", async () => {
    const setup = testAuth()
    await seedAccount(setup, { password: true })
    await seedAccount(setup, { identifier: "nopass@example.com" })
    const browser = new Browser(inProcess(setup.auth))
    await browser.start()
    const time = async (identifier: string, password: string) => {
      const start = performance.now()
      await browser.post("/auth/sign-in", { identifier, password })
      return performance.now() - start
    }
    const samples: Record<string, number[]> = {
      existing: [],
      missing: [],
      nopass: [],
      malformed: [],
    }
    const attempts: readonly (readonly [string, string, string])[] = [
      ["existing", "ada@example.com", "a wrong password"],
      ["missing", "missing@example.com", PASSWORD],
      ["nopass", "nopass@example.com", PASSWORD],
      ["malformed", "not an address", PASSWORD],
    ]
    // Interleaved, and each round starts with the next kind, so load from other processes and warm-up effects land on
    // every kind alike. 25 rounds keep the medians steady on a loaded machine; the bound below is unchanged.
    for (let round = 0; round < 25; round += 1) {
      for (let step = 0; step < attempts.length; step += 1) {
        const [kind, identifier, password] = attempts[(round + step) % attempts.length] as [
          string,
          string,
          string,
        ]
        samples[kind]?.push(await time(identifier, password))
      }
    }
    const reference = median(samples["existing"] ?? [])
    for (const kind of ["missing", "nopass", "malformed"]) {
      const ratio = median(samples[kind] ?? []) / reference
      expect([kind, ratio > 0.5 && ratio < 2]).toEqual([kind, true])
    }
  })
})
