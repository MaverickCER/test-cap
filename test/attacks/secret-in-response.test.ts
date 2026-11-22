// Attack: an error or alternate response path returns internal configuration, keys or client secrets.
// Stopped by: one error model with fixed public bodies; config objects never serialised (ADR 0003, 0015).
import { describe, expect, it } from "vitest"
import { memoryStore } from "../../src/store/memory.js"
import { Browser, ENV, hookedStore, inProcess, PASSWORD, testAuth } from "../support/auth.js"

const SECRET = "db.internal refused user admin with password hunter2"

describe("secret-in-response", () => {
  it("answers a store failure with a bare 500 that carries none of the error", async () => {
    const store = hookedStore(memoryStore(), (operation) =>
      operation === "createUnique"
        ? Promise.reject(new Error(`connection to ${SECRET} failed`))
        : Promise.resolve(),
    )
    const { auth } = testAuth({ store })
    const browser = new Browser(inProcess(auth))
    await browser.start()
    const reply = await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
    expect([reply.status, reply.text]).toEqual([500, '{"error":"internal"}'])
    expect([...reply.headers.values()].join("\n")).not.toContain("hunter2")
  })

  it("never puts a key, the configuration or a submitted secret in any reply", async () => {
    const { auth } = testAuth()
    const browser = new Browser(inProcess(auth))
    const replies = [await browser.get("/auth/session")]
    await browser.start()
    replies.push(
      await browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD }),
    )
    replies.push(
      await browser.post("/auth/sign-up", { identifier: "ada@example.com", extra: PASSWORD }),
    )
    replies.push(
      await browser.send({
        method: "POST",
        path: "/auth/sign-in",
        headers: [["Content-Type", "application/json"]],
        body: `{"password":"${PASSWORD}"`,
      }),
    )
    const everything = replies
      .map((reply) => `${reply.text}\n${[...reply.headers.values()].join("\n")}`)
      .join("\n")
    for (const secret of [
      ENV.AUTH_CSRF_KEY,
      ENV.AUTH_ENCRYPTION_KEY,
      ENV.AUTH_CSRF_KEY.slice(3),
      PASSWORD,
    ]) {
      expect(everything).not.toContain(secret)
    }
  })
})
