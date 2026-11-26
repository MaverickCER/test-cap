// The app the ZAP scans run against (ADR 0016, plan "Free tooling"): the built package behind Express with deny by
// default, over the memory store, in development mode. It serves test-cap's own routes and default pages, a public
// home page, and one protected page, which is everything an attacker on the network can reach.
//
// Node 22+: `node ci/zap/server.mjs` after `npm run build`. PORT (default 8080) and HOST (default 0.0.0.0, so the ZAP
// container can reach it) are read from the environment.
import express from "express"
import { createAuth } from "../../dist/index.js"
import { expressAuth } from "../../dist/express.js"
import { memoryStore } from "../../dist/store/memory.js"

const port = Number(process.env.PORT ?? 8080)
const auth = createAuth({
  store: memoryStore(),
  env: {
    APP_ENV: "development",
    APP_ORIGIN: `http://localhost:${String(port)}`,
    APP_SYSTEM_ID: "zap-scan",
  },
  // The breached-password check answers from memory, so a scan sends nothing to the internet.
  hibpFetch: async () => ({
    ok: true,
    status: 200,
    text: async () => "0000000000000000000000000000000000A:0",
  }),
  sendEmail: async () => {},
})

const app = express()
app.disable("x-powered-by")
app.use(expressAuth(auth, { public: ["/"] }))
// After expressAuth, so only the harness's own pages get these: the headers a real app sets, as test-cap's own
// responses carry, so the scan's findings are about test-cap and not about this harness.
app.use((_req, res, next) => {
  res.set({
    "Content-Security-Policy": "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  })
  next()
})
app.get("/", (_req, res) => {
  res.type("html").send('<!doctype html><title>Home</title><a href="/auth/sign-in">Sign in</a>')
})
app.get("/account", (req, res) => {
  res.type("text").send(`signed in as ${String(req.auth?.subject)}`)
})
app.listen(port, process.env.HOST ?? "0.0.0.0", () => {
  console.log(`listening on ${String(port)}`)
})
