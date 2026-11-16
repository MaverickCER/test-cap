# 0003: A byte transport contract, one dispatcher, and injected time and randomness

## Status

Accepted (2026-11-15). Implemented in phase 2 (the transport contract, the parsers, `Clock` and `RandomSource`),
phase 3 (the Express adapter) and phase 6 (the `fetch`, Nest, Next.js and TanStack Start adapters and the adapter
conformance suite).

Answers [handoff question](../../GLOSSARY.md) 3 (HTTP surface), together with ADR 0024, which owns the adapters and deny
by default.

Landed in phase 2: the transport cases are grouped in `test/transport/body.test.ts` and
`test/transport/headers-cookies-path.test.ts`, the clock, random and standard-globals scans in
`test/core/source-rules.test.ts`, and the parser exhaustion cases in
`test/attacks/request-parser-resource-exhaustion.test.ts` (a seeded generator; the fast-check port is phase 4). The
file names below are the original plan; the adapter and dispatcher rows remain for phases 3 and 6.

Planned tests:

- `test/transport/body-limit.test.ts` (a body over the limit is refused before it is parsed);
- `test/transport/content-type.test.ts` (only the accepted types are parsed; anything else is refused);
- `test/transport/cookies.test.ts` (parsing and serialising, including malformed and repeated cookies);
- `test/transport/set-cookie-multiple.test.ts` (several `Set-Cookie` values reach the client as separate headers);
- `test/transport/duplicate-headers.test.ts` (repeated request headers keep every value);
- `test/transport/abort-signal.test.ts` (an aborted request stops before its next store write);
- `test/transport/ambiguous-path.test.ts` (every ambiguous path form is a 400, under `/auth/*` and outside it);
- `test/transport/declared-fields.test.ts` (a body field the route does not declare is a 400);
- `test/transport/error-responses.test.ts` (each `TransportErrorCode` answers its status with a fixed body that holds
  no message);
- `test/transport/parsers.fuzz.test.ts` (fast-check over the form, JSON, cookie and header parsers);
- `test/adapters/conformance/*.test.ts` (every HTTP scenario through all five adapters);
- `test/attacks/upstream-body-parser-changes-core-view.test.ts` (an Express body parser mounted before test-cap cannot
  change what the core sees);
- `test/attacks/double-slash-path-bypass.test.ts` and `test/attacks/adapter-core-parsing-differential.test.ts`;
- `test/core/injected-clock-and-random.test.ts` (every flow runs on the injected `Clock` and `RandomSource`; a scan
  of `src/` finds no other use of the global clock or random source);
- `test/core/standard-globals-only.test.ts` (the core imports no `node:` module).

The recommendations under Open are provisional defaults until the owner decides.

## Context

The handoff asked the core to take plain inputs and return plain results, and to show framework support only through
example apps (question 3). Requirement 10 replaced that: adapters do 99% of the work and an app writes fewer than 20
lines (ADR 0024). The core must still hold all the logic, so that five adapters cannot drift into five
implementations.

The risk at this boundary is a parsing difference. If an adapter or a framework parses a request one way and the core
another, an attacker can send a request that the route check sees as one thing and the core as another: a
double-slash path, a body re-parsed by an app's own middleware, a header that appears twice. Better Auth's
double-slash advisory is one such case (ADR 0001).

Determinism is the other concern. Every flow depends on time (expiry, windows, TOTP steps) and on randomness (tokens,
challenges, codes). A flow that reads the global clock cannot be tested at the edges of its windows, and mutation
testing cannot kill a mutant that changes a comparison with the time.

## Decision

### 1. The transport contract works on bytes

```ts
type PlainRequest = {
  method: string
  url: string
  headers: Headers
  body: Uint8Array | null
  clientAddress?: string
  signal?: AbortSignal
}

type PlainResponse = { status: number; headers: Headers; body: Uint8Array | null }
```

`clientAddress` is the socket's address, never a forwarded header (ADR 0009).

Why: bytes are the one form every framework can hand over unchanged. A parsed body, a framework's cookie jar or its
request object would each carry that framework's parsing decisions into the core.

### 2. The core owns all parsing and validation

The core alone reads the content type, enforces the body size limit, parses forms and JSON, and parses and serialises
cookies. A body over the limit is refused before parsing. A content type the route does not accept is refused. A form
keeps a leading `?` as part of its first field name, and a form field whose percent escapes are malformed or do not
decode to UTF-8 is refused rather than read with replacement characters.
Each route declares the fields it reads; the core parses only those, and a body that carries any other field is
refused with a 400, so a request can never set a server-owned field such as a verified flag, a tenant or a status.

The core reads the path exactly as sent and never normalises it. A path that two parsers could read differently is
refused with a 400, for every request, whether under `/auth/*` or not, before deny by default (ADR 0024) or any route
sees it: an empty segment (`//`, or a trailing slash on any path but `/`), a dot segment, an encoded slash, dot or
backslash, a backslash, whitespace or a control character.

Why: one parser means one interpretation, and a declared field list means the request shape is the route's, not the
caller's. Normalising a path would be a bypass: `/admin/x/../about` normalises to a public `/about`, while a framework
may route the raw path to an `/admin/*` handler. Refusing it leaves nothing to disagree about. The fuzz tests and
the attack tests then cover every adapter at once.

### 3. Repeated headers and cookies are preserved

`headers` is a standard `Headers` object, so repeated request headers keep all their values. A response that sets
several cookies carries each `Set-Cookie` value separately (`Headers.getSetCookie()`), and every adapter writes them
as separate header lines.

Why: combining `Set-Cookie` values corrupts them, because cookie attributes contain commas. Dropping a repeated request
header hides exactly the ambiguity an attacker relies on.

### 4. The abort signal is honoured

When `signal` aborts, the core stops before its next store write and returns no success response for the work it did
not finish.

Why: a client that has gone away should not keep an argon2 slot or a store connection busy.

### 5. Adapters only convert

An adapter turns its framework's request into a `PlainRequest`, calls the core, and writes the `PlainResponse` back.
It holds no authentication logic. The Express adapter reads the raw request stream itself and never reads
`req.body`, so an app's body parser cannot change what the core sees.

The five adapters are `test-cap/express`, `test-cap/nest`, `test-cap/next`, `test-cap/tanstack-start` and
`test-cap/fetch`. An adapter conformance suite runs every HTTP scenario through all five; ADR 0024 records the deny by
default mode they share.

Why: the conformance suite can only prove adapters equivalent if they differ in nothing but conversion.

### 6. One dispatcher serves every auth route

`createAuth(config)` returns an `Auth`. Its `handle` member, `auth.handle(req)`, is the core's single entry for every
`/auth/*` route, the default pages and their hashed assets (ADR 0025). Its other members are owned elsewhere: `session`
by ADR 0006, `require` by ADR 0005, and `admin` by ADR 0012 and ADR 0014. Routing, CSRF checks (ADR 0011), headers and
caching rules (`no-store` on auth responses, immutable on hashed assets, ADR 0026) all live behind it.

Why: one entry gives one place to apply every check, and adapters stay a few lines long.

### 7. The core uses only Web Crypto and standard globals; time and randomness are injected

The core imports no `node:` module and no framework. It uses Web Crypto (`crypto.subtle`, `crypto.getRandomValues`)
and standard globals (`Headers`, `URL`, `TextEncoder`, `AbortSignal`).

`createAuth(config)` takes a `Clock` and a `RandomSource`. Every expiry, window, time step and timestamp reads the
`Clock`; every token, challenge, code and identifier draws from the `RandomSource`. The defaults read the system clock
and `crypto.getRandomValues`. Where a library accepts time or randomness, the injected source is passed in:
`oauth4webapi`'s `clockSkew` option is set from the `Clock`, and the WebAuthn challenge that `@simplewebauthn/server`
accepts from the caller is drawn from the `RandomSource`. The Limits section covers the libraries' own clock
reads.

Why: an injected clock lets a test stand exactly on either side of every expiry, so every flow is deterministic under
test and mutation testing can kill time- and randomness-dependent mutants. Standard globals are what lets the same
`dist/` run on Node, Bun and Deno (ADR 0023).

For tests, `fixedClock(start)` returns a `FixedClock` that a test sets and advances by hand, and
`sequenceRandom(bytes)` returns a `RandomSource` that replays fixed bytes.

Override: tests only. A test passes its own `Clock` and `RandomSource`; any other deployment mode refuses to start
with either (ADR 0026, section 4), because a frozen clock disables every expiry and a predictable random source makes
every token guessable.

### 8. One error model

A request the core refuses before any flow runs raises a `TransportError`. Its `code` is a `TransportErrorCode`, and
the dispatcher answers with the status that code maps to:

| `TransportErrorCode`                                                                                  | Status |
| ----------------------------------------------------------------------------------------------------- | ------ |
| `aborted`, `ambiguous-header`, `duplicate-field`, `invalid-path`, `malformed-body`, `too-many-fields` | 400    |
| `body-too-large`                                                                                      | 413    |
| `unsupported-media-type`                                                                              | 415    |

The response carries only the code, in a fixed public body; the error's message is for logs and never reaches the
client. An error a flow throws (a store, library or hook failure) gets a generic 500 body and never an `allow`
(ADR 0005). A configuration that cannot run raises one `ConfigError` at startup, whose `problems` list every reason at
once (ADR 0026).

Why: a fixed body per code leaks no configuration, stack, query, key or token, and listing every startup problem at
once saves a deploy-fix-deploy loop per problem.

Override: none.

## Consequences

- The quick start's adapter line is enough, because the adapter carries bytes and nothing else.
- A new framework needs only a converter and a pass of the adapter conformance suite.
- An app's body parser, path normaliser or cookie middleware has no effect on authentication.
- Every flow can be tested at its boundaries, and time-dependent mutants are killable.

## Limits

- **Library internals are outside the injected clock.** `oauth4webapi` and `@simplewebauthn/server` both call
  `Date.now()` internally. `clockSkew` offsets `oauth4webapi`'s reading but cannot replace it, and SimpleWebAuthn has
  no clock option. Full determinism in tests therefore needs the library options plus a test-time shim of the global
  clock, and the same holds for any other library that reads the clock itself (SAML is the likely case, ADR 0028). In
  production those libraries read the system clock, not the injected one, so an app that injects a skewed `Clock`
  gets test-cap's expiry checks and the libraries' checks on different times.
- **The status codes are coarse.** A client learns that a request was refused and which code applies, not which
  header or field caused it; the message in the log says.
- **Abort cannot undo a write in flight.** A store write already sent completes or fails on its own; the atomic
  operations of ADR 0002 keep it whole.
- **The Express adapter needs the raw stream.** If middleware mounted earlier has already consumed it, the adapter
  cannot recover the bytes; see Open.
- **Streaming bodies are not supported.** The body is read whole, up to the limit, which suits form and JSON auth
  routes and nothing larger.

## Open

1. **Body size limit.** The plan sets a limit but not its value. Recommendation: 64 KiB for every route, raised for
   the SAML assertion consumer route only (ADR 0028), and configurable downward only.
2. **A consumed stream in Express.** Recommendation: fail closed with an error that names the middleware order
   problem, rather than fall back to `req.body`.
3. **Repeated single-value headers and repeated fields.** Recommendation: the dispatcher refuses, rather than picks
   one of, a request with more than one `Host`, `Origin`, `Content-Type` or `Content-Length`, and a form or JSON body
   that repeats a field. Each refusal is a 400, so no two parsers can disagree on which value won. Ambiguous paths are
   no longer open: section 2 refuses them.
4. **What `auth.handle` returns outside its routes.** Recommendation: `null`, so an adapter passes the request on to
   the app (after the deny by default check of ADR 0024) without guessing from a status code.
