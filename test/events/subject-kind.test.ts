// INV-SUBJECT-KINDS-DISTINCT, the part phase 3 implements (specs/security-invariants.md; ADR 0013 §1): every session
// test-cap issues belongs to a person, and every event a flow reports names its subject's kind as `user`. The
// `service` and `agent` kinds have no flow until phase 8.
import { describe, expect, it } from "vitest"
import type { SecurityEvent } from "../../src/ocsf/events.js"
import { account, expectOk, PASSWORD, testAuth } from "../support/auth.js"
import { codeAt } from "../support/totp.js"

describe("subject kinds in phase 3", () => {
  it("names a user as the subject of every event sign-up, enrolment, sign-in, step-up and sign-out report", async () => {
    const setup = testAuth()
    const { browser, secret } = await account(setup)
    await expectOk(
      browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD }),
    )
    await expectOk(
      browser.post("/auth/totp/verify", { code: await codeAt(secret, setup.clock.now()) }),
    )
    await expectOk(browser.post("/auth/sign-out"))
    const kinds = (setup.events as SecurityEvent[]).map(
      (event) => event.unmapped.test_cap.subject_kind,
    )
    expect(kinds.length).toBeGreaterThan(5)
    expect(new Set(kinds)).toEqual(new Set(["user"]))
  })
})
