// Attack: sign-out or revoke acts on a session named by an unsigned cookie or a body value (BA GHSA-wmjr-v86c-m9jj).
// Stopped by: a session is found only by the SHA-256 of the presented `__Host-test-cap` token (ADR 0006).
import { describe, expect, it } from "vitest"
import { hexEncode, sha256, utf8Encode } from "../../src/core/encoding.js"
import { password } from "../support/evidence.js"
import { setup, TENANT } from "../support/sessions.js"

describe("forged-cookie-names-other-session", () => {
  it("signs out nothing when the cookie carries another session's id or hash instead of its token", async () => {
    const { sessions } = setup()
    const victim = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password()],
    })
    const hash = hexEncode(await sha256(utf8Encode(victim.token)))
    for (const forged of [victim.id, hash, hash.slice(0, 43)])
      await sessions.signOut(TENANT, forged)
    expect(await sessions.read(TENANT, victim.token)).not.toBeNull()
  })

  it("revokes another account's session by id from no session", async () => {
    const { sessions } = setup()
    const attacker = await sessions.signIn(TENANT, null, {
      subject: "acct-2",
      evidence: [password()],
    })
    const victim = await sessions.signIn(TENANT, null, {
      subject: "acct-1",
      evidence: [password()],
    })
    expect(await sessions.revoke(TENANT, attacker.token, victim.id)).toBe(false)
    expect(await sessions.read(TENANT, victim.token)).not.toBeNull()
  })
})
