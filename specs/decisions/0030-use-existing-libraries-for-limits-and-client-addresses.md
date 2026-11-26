# 0030: Use existing libraries for limits and client addresses

## Status

Accepted (2026-11-21), on the owner's direction of that day: where a package already works in every environment and
runtime test-cap supports, test-cap uses it instead of its own code. LogTape is the owner's example of the bar.
Implemented in phase 4. Amends [ADR 0009](0009-abuse-and-proxy-trust.md) §2, §3, §5, §7 and §8. Amended 2026-11-24 by
ADR 0009 §5: forwarded-parse reads each `Forwarded` element on its own, from the right, not the whole value. Pinned by:

- `test/security/store-limiter.test.ts`
- `test/security/rate-limit.test.ts`
- `test/core/dist-reach.test.ts`
- `test/core/client-address.test.ts`
- `test/abuse/client-address.test.ts`
- `test/topology/client-address.test.ts`
- `test/cross-runtime/exercised.mjs`
- `test/methods/password-hasher.test.ts`
- `test/methods/password-hasher-fallback.test.ts`
- `test/cross-runtime/journey.mjs`, run on workerd by `test/cross-runtime/workers.mjs`

## Context

Phase 4 first wrote every limit and the client-address parsing itself: a fixed-window counter and a doubling block for
the throttle, the failure ceiling and the request limits, an RFC 4291 IPv6 parser, CIDR matching and an RFC 7239
`Forwarded` parser. Each was tested, but each was code test-cap must keep correct alone, and an app that already runs
a limiter had to learn a second interface to plug it in.

The test of a library here is the one test-cap holds itself to: it runs unchanged on Node, Bun, Deno and Cloudflare
workerd, adds no dependency of its own, and is widely used. A probe on 2026-11-21 ran the same script on Node 22, Bun
1.3, Deno and workerd (through `wrangler dev`, with no `nodejs_compat` flag), with identical results: a custom store
subclass, a `RateLimiterUnion`, an IPv6 /64 match, a Cloudflare CIDR match, an IPv4-mapped address and RFC 7239
parsing.

| Library                 | Licence | Own dependencies | Downloads a week | Gzip for what test-cap imports |
| ----------------------- | ------- | ---------------- | ---------------- | ------------------------------ |
| `rate-limiter-flexible` | ISC     | none             | about 4.9M       | about 4.3 KB                   |
| `ipaddr.js`             | MIT     | none             | about 218M       | about 4.2 KB                   |
| `forwarded-parse`       | MIT     | none             | about 31M        | small                          |

## Decision

### 1. Limits run on rate-limiter-flexible

The request limits, the confirmation-mail send limits, the guessing throttle, the failure ceiling and the stuffing
detector's counts all count with rate-limiter-flexible 11.5.0. Its API (`consume`, `penalty`, `block`, `get`,
`delete`, a rejected `RateLimiterRes` for a refusal) is the one an app plugs in; test-cap has no limiter interface of
its own.

The default behind every limit is a store limiter test-cap ships, `createStoreLimiter`: a subclass of the library's
`RateLimiterStoreAbstract` over the app's `AuthStore`, so an app needs no infrastructure beyond the store it already
gave test-cap.

- A count is the port's atomic `increment`, in a fixed window per key; a duration of 0 counts in a window that never
  ends.
- A block is a record in `rate-limit-block`, and it never shortens a block already in place, so parallel failures
  settle on the longest. That is stricter than the library's own stores, whose `block` replaces.
- `get` reports a key's block, or `null`: the port reads a counter only by counting.
- It counts one point per call, as `increment` does, and refuses any other number.
- Time is test-cap's injected clock, so a test's fixed clock and the library agree.

The throttle follows the library's own pattern for login brute force: consecutive failures per account, per account
and client, and per client. Each attempt past the free ones takes the key's one point for the coming block (a
`consume` with a custom duration), so of a parallel burst one goes ahead; its `block` then holds the doubling delay,
and a success `delete`s the account's keys. The failure ceiling is a limiter of `failureCeiling` points that never
expire, blocked for good once they are spent and deleted by a success. The stuffing detector keeps its own logic,
because counting distinct accounts is not a counter the library offers, and counts both of its numbers with it.

**Override and replace.** A route's rule, and each mail limit, takes `{ windowMs, max }`, `false` where ADR 0009
allows it, a function of the request for routes, or any rate-limiter-flexible limiter: `RateLimiterRedis`, Postgres,
Drizzle, Prisma, Dynamo, Valkey, SQLite, Memory, or the app's own. `rateLimit` itself may be one limiter for every
route, and `limiter`, in `rateLimit` and `emailLimit`, is a factory that builds each rule's limiter over the app's own
backend from the library's own options, `{ points, duration, keyPrefix }`, keeping every default rule.

### 2. rate-limiter-flexible is imported by deep path only

test-cap imports `rate-limiter-flexible/lib/RateLimiterStoreAbstract.js` and `RateLimiterRes.js`, never the package.
Its index requires every store it ships, `RateLimiterCluster` among them, which loads Node's `cluster`.
`test/core/dist-reach.test.ts` walks every file each built entry reaches and fails on the package's index or on any
`node:` module.

### 3. Client addresses run on ipaddr.js and forwarded-parse

ipaddr.js 2.5.0 parses IPv4 and IPv6, reads an IPv4-mapped address as IPv4, and matches CIDR ranges; the /64 key is
built from its parts. forwarded-parse 2.2.0 parses `Forwarded` (RFC 7239). test-cap keeps what no runtime-agnostic
library has: the platform presets, the trust rules of ADR 0009 §5 and the diagnostics.

Three behaviours differ from the code they replace, each deliberately:

- **ipaddr.js reads `::192.0.2.10` as the IPv4-mapped `::ffff:192.0.2.10`.** RFC 4291 makes it `::c000:20a`, another
  client, so test-cap writes a dotted IPv4 tail as two hexadecimal groups before parsing.
- **A `Forwarded` element that is not RFC 7239 is `unknown`.** The old parser read hops out of malformed values (an
  unquoted IPv6 node, a stray quote, an empty element). Since 2026-11-24 each element is parsed on its own, from the
  right (ADR 0009 §5): parsing the whole value let a client that prepended a malformed element make the value
  unreadable, so it was counted under its proxy's address with every other client behind it. A malformed element the
  walk reaches is a hidden node, never a hop read out of it.
- **forwarded-parse requires Node's `util`**, for `util.inherits` and `util.format`. Bun, Deno and workerd provide it;
  the reach test allows that one built-in, from that one package, and no other.

### 4. Every version is pinned

The three packages are exact versions in `dependencies`. A change of version is a change to this decision's evidence:
the probe is run again on every runtime before it lands.

## Alternatives considered

| Alternative                               | Why it lost                                                                                |
| ----------------------------------------- | ------------------------------------------------------------------------------------------ |
| Keep test-cap's own limiter and parsers   | Correct and tested, but test-cap's alone to keep, and a second interface for apps to learn |
| `@upstash/ratelimit`                      | Needs Redis; test-cap's default must run on the app's store with nothing else              |
| `hono-rate-limiter`, `express-rate-limit` | Each is middleware for one framework; test-cap's core has no framework                     |
| `proxy-addr`                              | Reads Node's request object; test-cap's core has only the `PlainRequest`                   |
| `universal-rate-limit`                    | Runtime-agnostic, but about 1.3k downloads a week, too few to rest a security limit on     |

## Consequences

- An app plugs in the limiter it already runs, by the API it already knows, and test-cap's defaults keep working
  beside it.
- test-cap now depends on three more packages. Each is pinned, has no dependencies of its own, and is followed by the
  dependency checks (licences, SecurityDeps) like `hash-wasm`.
- The limits' store layout changed: counts keep their names (`throttle:client:<key>`, `ceiling:<id>`,
  `stuffing:<key>`), and blocks, reached ceilings and stuffing flags move to `rate-limit-block`.
- The store limiter's `block` never shortens, and its `get` sees blocks, not counts. An app that combines it with the
  library's own pieces gets those two differences.

## Limits

- **workerd is probed, not in CI.** The cross-runtime job runs Node, Bun and Deno. A workerd run needs wrangler or
  miniflare, which bring a platform binary and install scripts the dependency checks flag; a one-off run of the built
  `dist/` under workerd passed on 2026-11-21.
- **The library's in-memory block (`inMemoryBlockOnConsumed`) reads `Date.now`.** test-cap never sets it.
