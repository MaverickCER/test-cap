// Attack: a secondary issuance path mints access before the second factor. Stopped by: every route computes assurance
// from evidence, and a pre-auth or step-up-pending session mints nothing (ADR 0005, 0013).
import { describe, expect, it } from "vitest"
import { account, body, PASSWORD, testAuth } from "../support/auth.js"

describe("alternate-path-skips-second-factor", () => {
  it("gives a password-only session no session list, no recovery codes, no new authenticator and no access", async () => {
    const setup = testAuth()
    const { browser } = await account(setup)
    expect(
      (await browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD }))
        .json,
    ).toMatchObject({
      outcome: "step-up",
    })
    for (const [method, path] of [
      ["GET", "/auth/sessions"],
      ["POST", "/auth/recovery-codes"],
      ["POST", "/auth/totp/enrol"],
      ["POST", "/auth/sessions/revoke-others"],
    ] as const) {
      const reply = method === "GET" ? await browser.get(path) : await browser.post(path)
      expect(reply.status, path).toBeGreaterThanOrEqual(400)
      expect(reply.text, path).not.toMatch(/"codes"|"secret"|"sessions"/)
    }
    const session = body(await browser.get("/auth/session"))["session"]
    expect(session).toMatchObject({ state: "authenticated", level: "AAL1" })
    const request = new Request("https://app.example/billing", {
      headers: { cookie: [...browser.cookies].map(([n, v]) => `${n}=${v}`).join("; ") },
    })
    expect(
      (
        await setup.auth.require(
          { method: "GET", url: request.url, headers: request.headers, body: null },
          "default",
        )
      ).outcome,
    ).toBe("step-up")
  })
})
