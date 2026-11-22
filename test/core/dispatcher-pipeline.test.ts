// The dispatcher's shared checks (ADR 0003 §2, §6, §8; ADR 0011 §2): path, route, method, body fields and CSRF, in
// that order, on every route.
import { describe, expect, it } from "vitest"
import { CSRF_TOKEN_LIFETIME_MS } from "../../src/security/csrf.js"
import {
  body,
  Browser,
  inProcess,
  ORIGIN,
  testAuth,
  brief,
  CREATE,
  ENABLE_MFA,
  LOGON,
  LOGOFF,
  UPDATE,
} from "../support/auth.js"

describe("routing", () => {
  it.each(["/", "/about", "/authx", "/authentication/x", "/a/auth"])(
    "answers null outside the base path: %s",
    async (path) => {
      const { auth } = testAuth()
      expect(
        await auth.handle({ method: "GET", url: path, headers: new Headers(), body: null }),
      ).toBeNull()
    },
  )

  it.each([
    "//auth/session",
    "/auth//session",
    "/auth/./session",
    "/about/../auth/session",
    "/auth/session/",
    "/auth%2fsession",
    "/auth/sess%69on",
    "/x\\y",
    "/about/",
  ])("refuses the ambiguous path %s with a 400, inside the base path or not", async (path) => {
    const { auth } = testAuth()
    const reply = await new Browser(inProcess(auth)).get(path)
    expect([reply.status, reply.text]).toEqual([400, '{"error":"invalid-path"}'])
    expect(reply.headers.get("cache-control")).toBe("no-store")
  })

  it.each(["/auth", "/auth/nope", "/auth/session/x", "/auth/totp", "/auth/SESSION"])(
    "answers 404 for an unknown route: %s",
    async (path) => {
      const { auth } = testAuth()
      const reply = await new Browser(inProcess(auth)).get(path)
      expect([reply.status, reply.text]).toEqual([404, '{"error":"not-found"}'])
    },
  )

  it.each([
    ["GET", "/auth/totp/verify", "POST"],
    ["GET", "/auth/email/resend", "POST"],
    ["PUT", "/auth/sign-in", "GET, POST"],
    ["HEAD", "/auth/email/confirm", "GET, POST"],
    ["POST", "/auth/session", "GET"],
    ["HEAD", "/auth/session", "GET"],
    ["OPTIONS", "/auth/sessions", "GET"],
    ["post", "/auth/sign-out", "GET, POST"],
  ])("answers 405 for %s %s, naming the method in Allow", async (method, path, allow) => {
    const { auth } = testAuth()
    const reply = await new Browser(inProcess(auth)).send({ method, path })
    expect([reply.status, reply.text, reply.headers.get("allow")]).toEqual([
      405,
      '{"error":"method-not-allowed"}',
      allow,
    ])
  })
})

describe("transport refusals", () => {
  it("answers each with its status and fixed code", async () => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth))
    await browser.start()
    const send = (contentType: string, payload: string) =>
      browser.send({
        method: "POST",
        path: "/auth/sign-up",
        headers: [
          ["Origin", ORIGIN],
          ["Content-Type", contentType],
          ["X-CSRF-Token", browser.csrf ?? ""],
        ],
        body: payload,
      })
    const tooLarge = await send("application/json", `{"identifier":"${"a".repeat(70_000)}"}`)
    expect([tooLarge.status, tooLarge.text]).toEqual([413, '{"error":"body-too-large"}'])
    const plain = await send("text/plain", "identifier=a")
    expect([plain.status, plain.text]).toEqual([415, '{"error":"unsupported-media-type"}'])
    const broken = await send("application/json", "{")
    expect([broken.status, broken.text]).toEqual([400, '{"error":"malformed-body"}'])
    const repeated = await send("application/x-www-form-urlencoded", "identifier=a&identifier=b")
    expect([repeated.status, repeated.text]).toEqual([400, '{"error":"duplicate-field"}'])
  })
})

describe("declared fields (ADR 0003 §2)", () => {
  it("refuses a field the route does not declare", async () => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth))
    await browser.start()
    const reply = await browser.post("/auth/sign-up", {
      identifier: "ada@example.com",
      status: "x",
    })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"undeclared-field"}'])
  })

  it("refuses a field that is not a string, the token included", async () => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth))
    await browser.start()
    const number = await browser.post("/auth/sign-up", { identifier: 7 })
    expect([number.status, number.text]).toEqual([400, '{"error":"invalid-field"}'])
    const token = await browser.send({
      method: "POST",
      path: "/auth/sign-up",
      headers: [
        ["Origin", ORIGIN],
        ["Content-Type", "application/json"],
      ],
      body: JSON.stringify({ identifier: "ada@example.com", csrfToken: 1 }),
    })
    expect([token.status, token.text]).toEqual([400, '{"error":"invalid-field"}'])
  })

  it("refuses a request missing a required field", async () => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth))
    await browser.start()
    const reply = await browser.post("/auth/sign-in", { identifier: "ada@example.com" })
    expect([reply.status, reply.text]).toEqual([400, '{"error":"missing-field"}'])
  })

  it("accepts a route's optional fields", async () => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth))
    await browser.start()
    const reply = await browser.post("/auth/sign-up", {
      identifier: "ada@example.com",
      returnTo: "/next",
    })
    expect(body(reply)).toEqual({ outcome: "enroll", returnTo: "/next" })
  })
})

describe("CSRF (ADR 0011 §2)", () => {
  const signUp = (
    browser: Browser,
    headers: [string, string][],
    payload: Record<string, unknown>,
  ) =>
    browser.send({
      method: "POST",
      path: "/auth/sign-up",
      headers: [["Content-Type", "application/json"], ...headers],
      body: JSON.stringify({ identifier: "ada@example.com", ...payload }),
    })

  it("accepts the token in the header with Origin, or in the body with Sec-Fetch-Site", async () => {
    const { auth } = testAuth()
    const first = new Browser(inProcess(auth))
    await first.start()
    expect(
      (
        await signUp(
          first,
          [
            ["Origin", ORIGIN],
            ["X-CSRF-Token", first.csrf ?? ""],
          ],
          {},
        )
      ).status,
    ).toBe(200)
    const second = new Browser(inProcess(auth))
    await second.start()
    const reply = await signUp(second, [["Sec-Fetch-Site", "same-origin"]], {
      csrfToken: second.csrf,
    })
    expect(reply.status).toBe(200)
  })

  it.each([
    ["no Origin and no Sec-Fetch-Site", (token: string) => [["X-CSRF-Token", token]]],
    [
      "another Origin",
      (token: string) => [
        ["Origin", "https://evil.example"],
        ["X-CSRF-Token", token],
      ],
    ],
    [
      "Sec-Fetch-Site cross-site",
      (token: string) => [
        ["Sec-Fetch-Site", "cross-site"],
        ["X-CSRF-Token", token],
      ],
    ],
    ["no token", () => [["Origin", ORIGIN]]],
    [
      "a token for another binding",
      () => [
        ["Origin", ORIGIN],
        ["X-CSRF-Token", `c1.9999999999999.${"A".repeat(43)}`],
      ],
    ],
  ] as const)("refuses %s with a 403 and a failure event", async (_name, headers) => {
    const { auth, events } = testAuth()
    const browser = new Browser(inProcess(auth))
    await browser.start()
    const reply = await signUp(browser, headers(browser.csrf ?? "") as [string, string][], {})
    expect([reply.status, reply.text]).toEqual([403, '{"error":"csrf"}'])
    expect(events.map(brief)).toEqual([
      { type: CREATE, status: "Failure", user: "unknown", detail: "csrf" },
    ])
  })

  it("refuses a token sent in both the header and the body", async () => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth))
    await browser.start()
    const token = browser.csrf ?? ""
    const reply = await signUp(
      browser,
      [
        ["Origin", ORIGIN],
        ["X-CSRF-Token", token],
      ],
      { csrfToken: token },
    )
    expect(reply.status).toBe(403)
  })

  it("refuses a token issued to another browser", async () => {
    const { auth } = testAuth()
    const attacker = new Browser(inProcess(auth))
    await attacker.start()
    const victim = new Browser(inProcess(auth))
    await victim.start()
    const reply = await signUp(
      victim,
      [
        ["Origin", ORIGIN],
        ["X-CSRF-Token", attacker.csrf ?? ""],
      ],
      {},
    )
    expect(reply.status).toBe(403)
  })

  it("refuses any token from a browser holding neither a session nor a pre-session cookie", async () => {
    const { auth } = testAuth()
    const other = new Browser(inProcess(auth))
    await other.start()
    const bare = new Browser(inProcess(auth))
    const reply = await signUp(
      bare,
      [
        ["Origin", ORIGIN],
        ["X-CSRF-Token", other.csrf ?? ""],
      ],
      {},
    )
    expect(reply.status).toBe(403)
  })

  it("refuses a token an hour old", async () => {
    const { auth, clock } = testAuth()
    const browser = new Browser(inProcess(auth))
    await browser.start()
    clock.advance(CSRF_TOKEN_LIFETIME_MS)
    expect((await browser.post("/auth/sign-up", { identifier: "ada@example.com" })).status).toBe(
      403,
    )
  })

  it.each([
    ["/auth/sign-up", CREATE],
    ["/auth/email/confirm", UPDATE],
    ["/auth/email/resend", UPDATE],
    ["/auth/password", ENABLE_MFA],
    ["/auth/totp/enrol", ENABLE_MFA],
    ["/auth/totp/confirm", ENABLE_MFA],
    ["/auth/sign-in", LOGON],
    ["/auth/totp/verify", LOGON],
    ["/auth/step-up/start", LOGON],
    ["/auth/step-up", LOGON],
    ["/auth/sign-out", LOGOFF],
    ["/auth/sessions/revoke", LOGOFF],
  ])("counts a refused %s as a failure of %s (ADR 0015 §2)", async (path, kind) => {
    const { auth, events } = testAuth()
    const reply = await new Browser(inProcess(auth)).send({ method: "POST", path })
    expect(reply.status).toBe(403)
    expect(events.map(brief)).toEqual([
      { type: kind, status: "Failure", user: "unknown", detail: "csrf" },
    ])
  })
})

describe("each route's fields", () => {
  const REQUIRED: Record<string, readonly string[]> = {
    "/auth/sign-up": ["identifier"],
    "/auth/email/confirm": ["code"],
    "/auth/password": ["password"],
    "/auth/totp/confirm": ["authenticatorId", "code"],
    "/auth/sign-in": ["identifier", "password"],
    "/auth/totp/verify": ["code"],
    "/auth/step-up": ["challenge"],
    "/auth/sessions/revoke": ["sessionId"],
  }

  it.each(
    Object.entries(REQUIRED).flatMap(([path, fields]) =>
      fields.map((field) => [path, field, fields] as const),
    ),
  )("%s requires %s", async (path, missing, fields) => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth))
    await browser.start()
    const sent = Object.fromEntries(
      fields.filter((field) => field !== missing).map((field) => [field, "x"]),
    )
    const reply = await browser.post(path, sent)
    expect([reply.status, reply.text]).toEqual([400, '{"error":"missing-field"}'])
  })

  it.each([
    ["/auth/sign-up", { identifier: "x" }],
    ["/auth/password", { password: "x" }],
    ["/auth/totp/enrol", {}],
    ["/auth/totp/confirm", { authenticatorId: "A".repeat(43), code: "x" }],
    ["/auth/sign-in", { identifier: "x", password: "x" }],
    ["/auth/totp/verify", { code: "x" }],
    ["/auth/step-up/start", {}],
    ["/auth/step-up", { challenge: "x", code: "x" }],
    ["/auth/step-up", { challenge: "x", password: "x" }],
    ["/auth/sign-out", {}],
    ["/auth/sessions/revoke", { sessionId: "x" }],
  ] as const)("%s needs nothing beyond %j", async (path, sent) => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth))
    await browser.start()
    const reply = await browser.post(path, sent)
    expect(reply.text).not.toMatch(/missing-field|undeclared-field/)
  })

  it.each(["/auth/totp/enrol", "/auth/step-up/start", "/auth/sign-out"])(
    "%s declares no field",
    async (path) => {
      const { auth } = testAuth()
      const browser = new Browser(inProcess(auth))
      await browser.start()
      const reply = await browser.post(path, { "Stryker was here": "x" })
      expect(reply.text).toBe('{"error":"undeclared-field"}')
    },
  )
})
