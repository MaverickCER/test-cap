// Attack: an app body parser consumes or rewrites the body before the core reads it.
// Stopped by: the Express adapter reads the raw stream; a pre-parsed body is refused, not trusted (ADR 0003, 0024).
import express, { type RequestHandler } from "express"
import { afterEach, describe, expect, it } from "vitest"
import { expressAuth } from "../../src/adapters/express/index.js"
import { body, Browser, testAuth } from "../support/auth.js"
import { listen } from "../support/http.js"

const closers: (() => Promise<void>)[] = []
afterEach(async () => {
  await Promise.all(closers.splice(0).map((close) => close()))
})

async function withUpstream(upstream: RequestHandler) {
  const setup = testAuth()
  const app = express()
  app.use(upstream)
  app.use(expressAuth(setup.auth))
  const server = await listen(app)
  closers.push(server.close)
  const browser = new Browser(server.transport)
  await browser.start()
  return { setup, browser }
}

describe("upstream-body-parser-changes-core-view", () => {
  it.each([
    ["express.json()", express.json(), false],
    ["express.urlencoded()", express.urlencoded({ extended: true }), true],
    ["express.raw()", express.raw({ type: "*/*" }), false],
  ])("fails closed when %s read the body first", async (_name, parser, form) => {
    const { setup, browser } = await withUpstream(parser)
    const reply = form
      ? await browser.postForm("/auth/sign-up", { identifier: "ada@example.com" })
      : await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
    expect([reply.status, reply.text]).toEqual([500, '{"error":"body-already-read"}'])
    expect(setup.events).toEqual([])
  })

  it("refuses a middleware that sets req.body without reading the stream, never trusting it", async () => {
    const { setup, browser } = await withUpstream((req, _res, next) => {
      if (req.method === "POST") {
        ;(req as { body?: unknown }).body = { identifier: "attacker@example.com", verified: true }
      }
      next()
    })
    const reply = await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
    expect(reply.status).toBe(500)
    expect(setup.events).toEqual([])
  })

  it("sees the bytes as sent when an upstream parser skipped the content type", async () => {
    const { browser } = await withUpstream(express.text())
    const reply = await browser.post("/auth/sign-up", { identifier: "ada@example.com" })
    expect([reply.status, body(reply)]).toEqual([200, { outcome: "enroll", returnTo: "/" }])
  })
})
