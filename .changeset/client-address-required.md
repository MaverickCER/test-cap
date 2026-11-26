---
"test-cap": minor
---

Production and staging need a client address for the per-client limits (ADR 0009 §8, Open 4).

**Breaking:** in production or staging, an app on `fetchAuth`, `withAuth`, `nextAuthHandler` or `tanstackStartAuth`
that passes no `clientAddress`, and uses no `vercel`, `fly` or `netlify` preset, no longer starts. Pass
`clientAddress`, or set `requireClientAddress: false` if a gateway in front of the app limits requests.

- **The new `requireClientAddress` option**, `true` by default. In production and staging, `fetchAuth`, `withAuth`,
  `nextAuthHandler` and `tanstackStartAuth` refuse to start with a `ConfigError` when they have no `clientAddress`
  option, unless the platform preset is `vercel`, `fly` or `netlify`. A request that still arrives with no client
  address gets the fixed 500 before it is counted or run. `requireClientAddress: false` serves it uncounted, for an
  app that limits requests at its gateway. Development and test serve it uncounted, as before.
- **Operator diagnostics**: the new code `client-address-optional` reports `requireClientAddress: false` once. The
  `client-address-missing` message now says whether the request was refused or served uncounted.
- **`Forwarded` is read one element at a time from the right**, as `X-Forwarded-For` is. A client that prepends a
  malformed element can no longer make the whole value unreadable and be counted under its proxy's address. A
  malformed element the walk reaches is `unknown`.
