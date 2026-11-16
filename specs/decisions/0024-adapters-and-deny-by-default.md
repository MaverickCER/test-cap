# 0024: Adapters and deny by default

## Status

Accepted (2026-11-15). Supersedes the handoff's "no framework or runtime adapters" rule. Implemented in phase 3 (the
Express adapter with deny by default) and phase 6 (the `fetch`, Nest, Next.js and TanStack Start adapters and the
adapter conformance suite); the quick-start count runs from phase 7. Flow: F22 (adapter transport and deny by
default). Pinned by:

- `test/adapters/conformance/*.test.ts`
- `test/adapters/deny-by-default.test.ts`
- `test/adapters/public-paths.test.ts`
- `test/adapters/tanstack-start-server-functions.test.ts`
- `test/adapters/next-surfaces.test.ts`
- `test/attacks/upstream-body-parser.test.ts`
- `test/attacks/double-slash-path.test.ts`
- `test/attacks/adapter-core-parsing-difference.test.ts`
- `test/docs/next-proxy-not-protection.test.ts`
- `test/docs/quick-start-lines.test.ts`

## Context

The handoff ruled out framework and runtime adapters: one framework-free core with plain inputs, and framework support
shown only by example apps. Its reasons were sound. Authentication logic in five adapters is five places for a bypass,
and a parsing difference between an adapter and the core is a known attack class.

Owner requirement 10 overrides the rule: adapters do 99% of the work, so an app imports one and writes fewer than 20
lines. The two goals meet at the transport contract ([ADR 0003](0003-byte-transport-and-dispatcher.md)). The core takes
a `PlainRequest` of bytes and returns a `PlainResponse`, and owns all parsing. An adapter that only converts a
framework's request into bytes, and bytes back into a framework's response, adds lines an app no longer writes without
adding a place for authentication logic.

## Decision

### 1. Five adapters, each a byte converter

| Entry                     | Converts                                    | Deny by default                        |
| ------------------------- | ------------------------------------------- | -------------------------------------- |
| `test-cap/express`        | Node request and response                   | `expressAuth(auth, { public: [...] })` |
| `test-cap/nest`           | Nest's underlying HTTP request and response | a global guard plus `@Public()`        |
| `test-cap/next`           | the Web `Request` and `Response`            | see section 4                          |
| `test-cap/tanstack-start` | the Web `Request` and `Response`            | global middleware                      |
| `test-cap/fetch`          | the Web `Request` and `Response`            | a wrapper around the app's handler     |

Each adapter builds a `PlainRequest` (method, URL, headers, body bytes, client address, abort signal), calls the core,
and writes the `PlainResponse` back. It keeps duplicate headers and every `Set-Cookie` value, and passes the abort
signal through. It never parses a body, reads a cookie, or decides anything.

The Express adapter reads the raw request stream itself, so an app's body parser cannot change what the core sees.

Why: the logic stays in one core that every adapter shares, so a fix lands once and a test of the core is a test of
every adapter.

Override: an app that wants no adapter calls `auth.handle(req)` with its own `PlainRequest`.

### 2. Deny by default, in every adapter

Every adapter can protect every route at the default requirement (AAL2) unless the route is listed as public. The
adapter passes the public list to the core, and the core matches it against the path it normalised itself, so the five
adapters cannot disagree about which path is public. Routes under `/auth/*`, the default pages and their hashed assets
are served by the dispatcher and need no listing.

Why: an app that forgets to protect a route should get a protected route. Matching in the core keeps the double-slash
class of bypass (a path the adapter and the core read differently) out of reach.

Override: the app lists public paths, and calls `auth.require(req, requirementId)` for a route that needs more than
the default.

### 3. One conformance suite for all five

The adapter conformance suite runs every HTTP scenario through all five adapters and expects the same `PlainResponse`.
It checks that a body parsed upstream cannot change the core's view, that duplicate headers and cookies survive, that
the abort signal is honoured, and that deny by default holds.

Why: "only converts bytes" is a claim about five pieces of code; the suite is how it stays true.

### 4. Next.js has three surfaces, and `proxy` is never protection

- **The route handler** serves `/auth/*`, the default pages and the assets.
- **Authoritative server helpers** check the session and requirement inside route handlers, server functions and the
  app's data-access layer, close to the data.
- **An optional `proxy`** may redirect early, for example sending a signed-out visitor to the sign-in page.

The docs never claim that `proxy` protects a route. Next.js 16's own docs say it "should not be your only line of
defense", and a docs test fails if test-cap's docs say otherwise.

Why: a redirect in `proxy` improves the experience; only a check next to the data protects it.

Override: the app chooses whether to use `proxy`.

### 5. Under 20 lines

The README quick start, an Express app with a SQL store and deny by default, runs in CI. A test counts its lines and
fails at 20 or more.

Why: requirement 10 names the number; a test keeps it.

## Consequences

- An app adopts test-cap with one adapter import and one `use` (or its framework's equivalent).
- Adding a sixth adapter means a converter and passing the conformance suite, nothing more.
- Five adapters are five dependencies on framework behaviour. A framework release that changes how it hands over the
  raw body or headers fails the suite rather than silently changing what the core sees.

## Limits

- **Next.js has no authoritative global check.** Deny by default there covers what the route handler and the server
  helpers cover. A server function or route handler that never calls a helper is unprotected, and nothing in Next.js
  forces the call. This requirement is only partly met for Next.js.
- **TanStack Start's global middleware** must reach server functions as well as server routes. A version that runs
  server functions outside it would leave them unprotected; `test/adapters/tanstack-start-server-functions.test.ts`
  pins the behaviour for the supported version.
- **The adapters convert; they do not secure the framework.** Framework vulnerabilities outside the request path
  test-cap sees remain the app's.
- **Runtime support per adapter** is not yet stated ([ADR 0023](0023-runtime-support-per-capability.md), Open 1).

## Open

1. **How public paths match.** The plan's example `public: ["/", "/about"]` would make every route public if `/` were a
   prefix. Recommendation: exact match after the core's normalisation (repeated slashes, encoded slashes, dot segments,
   a trailing slash), with an explicit wildcard form such as `"/blog/*"` for prefixes.
2. **A body parser that ran first.** When an app mounts a body parser before the Express adapter, the raw stream is
   already consumed. Recommendation: the adapter fails closed with a `500` and a clear development error, and never
   rebuilds the body from `req.body`.
3. **Nest and the raw body.** Nest parses bodies by default. Recommendation: the Nest adapter mounts the dispatcher on
   the underlying HTTP instance ahead of Nest's body parser, as the Express adapter does.
4. **Next.js routes that skip the helper.** Recommendation: the Next.js example's e2e tests request every route signed
   out, and a later lint rule flags a server function or route handler that never calls a helper.
