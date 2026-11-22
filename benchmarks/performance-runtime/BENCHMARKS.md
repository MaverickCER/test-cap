# test-cap: performance and cost report

What does adopting this package add to latency, CPU, memory and compute spend, and how does that grow with workload? Three views, from the whole to the part: **(1)** the end-to-end total, **(2)** every function on its own, **(3)** which functions make up the total. New to benchmarks? Read [READING-BENCHMARKS.md](../READING-BENCHMARKS.md) first.

## What adopting this package costs

For a typical workload of **640 requests** per operation, routing the work through `test-cap` adds **21.3 ms** per operation compared with a bare-minimum baseline (**516× the baseline**). Overall, it grows O(n) with workload size (measured exponent 0.99). At list prices that is on the order of **~$0.1 per million operations** of compute.

> The relative figure and the growth class are the steadier ones. Both come from the same run, so they depend far less on the machine than a time does. Runtime behaviour and contention on the runner still move them. The growth class is an empirical fit to the sizes tested, not a proof of asymptotic complexity. Dollar figures are **order-of-magnitude** estimates from published list prices on shared hardware (see _Cost model_ below). They show scale, not a budget.

| Cost | Typical (640 requests) | Largest (10240 requests) |
| --- | --- | --- |
| Added latency per operation | 21.3 ms | 335 ms |
| Added latency, relative to baseline | 516× baseline | 555× baseline |
| Added CPU time per operation | 26.7 ms | 353 ms |
| Added memory per operation (heap delta) | 996.3 KiB | 14.5 MiB |
| Compute cost per 1M operations (order of magnitude) | ~$0.1 | ~$1 – $10 |
| Single-core throughput ceiling of the overhead alone | 47 ops/s | 3 ops/s |
| Shipped code parsed at every cold start (gzip) | 5.0 KiB | 5.0 KiB |

## 1. End-to-end: the package's total impact

What an app pays per request for routing it through test-cap instead of answering it itself: n requests for the session and a CSRF token, the request every page load makes first.

- **Baseline (no package):** n calls of an async function that returns a fixed response, with no package involved.
- **With the package:** n GET /auth/session requests through auth.handle: path check, cookie parse, session read, CSRF token, security headers.

Both sides use empty or minimal functions on purpose. The difference is then the package's own cost, not the cost of the work an application would plug into it. Real applications add their own work on top; this is the floor the package imposes.

**Variables that could change this result**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| requests | swept | The tier axis: requests per operation. |
| session | fixed at "none" | Each request carries no cookie, so the store lookup misses: the first visit every browser makes. |
| runtime | fixed at "node" | Measured on Node only; Bun and Deno are covered for correctness by the cross-runtime job, not timed. |

The baseline is an empty or minimal function, so it costs almost nothing. The _relative_ overhead can then look enormous (shown as a multiple of the baseline). Read the absolute columns (time, CPU and dollars added): they are what a bill and a latency budget are made of.

| requests | Baseline | With package | Added | Added vs baseline | Added CPU | Est. $ / 1M ops |
| --- | --- | --- | --- | --- | --- | --- |
| 20 | 3.92 µs | 972 µs | 970 µs | 249× baseline | 2.67 ms | $0.002 – $0.030 |
| 40 | 4.29 µs | 1.51 ms | 1.50 ms | 351× baseline | 3.08 ms | $0.0031 – $0.035 |
| 80 | 7.42 µs | 2.96 ms | 2.95 ms | 399× baseline | 4.56 ms | $0.0061 – $0.051 |
| 160 | 13.5 µs | 5.88 ms | 5.86 ms | 435× baseline | 7.70 ms | $0.012 – $0.087 |
| 320 | 23.8 µs | 11.0 ms | 11.0 ms | 462× baseline | 16.0 ms | $0.023 – $0.180 |
| 640 | 41.4 µs | 21.4 ms | 21.3 ms | 516× baseline | 26.7 ms | $0.044 – $0.301 |
| 1280 | 80.4 µs | 42.8 ms | 42.7 ms | 532× baseline | 48.4 ms | $0.089 – $0.545 |
| 2560 | 152 µs | 85.1 ms | 85.0 ms | 560× baseline | 97.7 ms | $0.177 – $1.10 |
| 5120 | 306 µs | 166 ms | 166 ms | 544× baseline | 179 ms | $0.346 – $2.02 |
| 10240 | 605 µs | 336 ms | 335 ms | 555× baseline | 353 ms | $0.699 – $3.97 |

**How the total grows:** O(n) (linear), exponent 0.99 over 10 sizes.

## 2. Function by function

Every function the package exposes is measured on its own across the full size ladder. Its measured growth rate is then compared with the big-O we documented for it. A function whose measured class **differs** from its documented one is the most useful thing in this report. Either the documentation or the code is wrong.

| Function | Varies | Documented | Measured | Agreement | At 640 | At 10240 |
| --- | --- | --- | --- | --- | --- | --- |
| `auth.handle (GET /auth/session)` | request | O(n) | O(n) | ✅ matches | 180 µs | 2.45 ms |
| `auth.handle (POST /auth/sign-up)` | request | O(1) | O(1) | ✅ matches | 485 µs (at 254) | 485 µs (at 254) |
| `auth.handle (POST /auth/sign-in)` (test-cost) | request | O(1) | O(1) | ✅ matches | 355 µs (at 256) | 355 µs (at 256) |
| `auth.handle (POST /auth/sign-in)` (real-cost) | request | O(1) | O(1) | ✅ matches | 33.0 ms (at 256) | 33.0 ms (at 256) |
| `createAuth` | request | O(n) | O(n) | ✅ matches | 6.27 ms | 94.3 ms |
| `defineAuthPolicy` | request | O(n) | O(n log n) | 🟡 close (neighbouring class) | 99.1 µs | 3.98 ms |
| `expressAuth` | request | O(n) | O(n) | ✅ matches | 28.2 µs | 259 µs |
| `expressAuth (per request)` (auth-route) | request | O(n) | O(n) | ✅ matches | 34.1 ms | 504 ms |
| `expressAuth (per request)` (public-route) | request | O(n) | O(n) | ✅ matches | 604 µs | 9.63 ms |
| `expressAuth (per request)` (protected-route) | request | O(n) | O(n) | ✅ matches | 10.5 ms | 121 ms |
| `withAuth` (auth-route) | request | O(n) | O(n) | ✅ matches | 30.2 ms | 439 ms |
| `withAuth` (public-route) | request | O(n) | O(n) | ✅ matches | 429 µs | 7.12 ms |
| `withAuth` (protected-route) | request | O(n) | O(n) | ✅ matches | 8.63 ms | 118 ms |
| `fetchAuth` (auth-route) | request | O(n) | O(n) | ✅ matches | 29.3 ms | 438 ms |
| `fetchAuth` (outside-auth) | request | O(n) | O(n) | ✅ matches | 370 µs | 6.22 ms |
| `nextAuthHandler` | request | O(n) | O(n) | ✅ matches | 29.6 ms | 436 ms |
| `nextProxy` (public-route) | request | O(n) | O(n) | ✅ matches | 291 µs | 4.81 ms |
| `nextProxy` (redirect) | request | O(n) | O(n) | ✅ matches | 1.44 ms | 22.0 ms |
| `nextProxy` (session-cookie) | request | O(n) | O(n) | ✅ matches | 640 µs | 10.1 ms |
| `nextServerAuth` (session) | request | O(n) | O(n) | ✅ matches | 732 µs | 11.7 ms |
| `nextServerAuth` (require) | request | O(n) | O(n) | ✅ matches | 786 µs | 12.6 ms |
| `tanstackStartAuth` (route-handler) | request | O(n) | O(n) | ✅ matches | 30.9 ms | 438 ms |
| `tanstackStartAuth` (session) | request | O(n) | O(n) | ✅ matches | 301 µs | 4.84 ms |
| `tanstackStartAuth` (require) | request | O(n) | O(n) | ✅ matches | 332 µs | 5.37 ms |
| `tanstackStartMiddleware` (auth-route) | request | O(n) | O(n) | ✅ matches | 532 µs | 8.82 ms |
| `tanstackStartMiddleware` (public-route) | request | O(n) | O(n) | ✅ matches | 390 µs | 7.20 ms |
| `tanstackStartMiddleware` (protected-route) | request | O(n) | O(n) | ✅ matches | 8.86 ms | 118 ms |
| `auth.handle (POST /auth/totp/verify)` (newest-matches) | request | O(n) | O(log n) | 🟡 close (neighbouring class) | 1.67 ms (at 5) | 1.67 ms (at 5) |
| `auth.handle (POST /auth/totp/verify)` (wrong-code) | request | O(n) | O(log n) | 🟡 close (neighbouring class) | 1.37 ms (at 5) | 1.37 ms (at 5) |
| `auth.require` | request | O(n) | O(log n) | 🟡 close (neighbouring class) | 90.6 µs (at 5) | 90.6 µs (at 5) |
| `memoryStore().listByOwner` | request | O(n) | O(n) | ✅ matches | 1.08 ms | 17.0 ms |
| `memoryStore().consumeOnce` | request | O(1) | O(log n) | 🟡 close (neighbouring class) | 13.5 µs | 28.2 µs |
| `memoryStore().increment` | request | O(1) | O(1) | ✅ matches | 0.735 µs | 0.725 µs |

### `auth.handle (GET /auth/session)`

**Why we benchmark it.** Every page load asks for the session and a CSRF token first, so the cookie parser and the session read run on every request a browser makes. A browser sends every cookie the app's domain holds, often dozens.

**What poor performance would mean.** A parser that grew faster than the cookie header would let a client with many cookies slow every request, and an attacker could send a large Cookie header to burn server time.

**Expected growth: O(n).** The Cookie header is split once and each pair is checked once for the session and pre-session names, so the work grows with the number of cookies.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| cookies | swept | Cookies in the request's Cookie header, none of them test-cap's. |
| session | fixed at "none" | No session cookie, the first-visit path. |

**Deliberately not covered**

- **a live session**: Reading a stored session is one memory-store get; the store benchmarks below measure it with n records.

**In the end-to-end run:** One per request in the end-to-end run.

**Measured: O(n)** (exponent 0.95, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 50.6 µs | 124 µs | 53.0 µs | 34.3 KiB | 19,760 |
| 40 | 53.7 µs | 95.1 µs | 104 µs | 41.0 KiB | 18,619 |
| 80 | 58.8 µs | 81.7 µs | 257 µs | 52.7 KiB | 17,014 |
| 160 | 72.3 µs | 86.4 µs | 219 µs | 80.0 KiB | 13,822 |
| 320 | 109 µs | 124 µs | 307 µs | 133.0 KiB | 9,146 |
| 640 | 180 µs | 201 µs | 500 µs | 253.9 KiB | 5,558 |
| 1280 | 326 µs | 352 µs | 858 µs | 504.9 KiB | 3,071 |
| 2560 | 623 µs | 650 µs | 1.39 ms | 944.6 KiB | 1,606 |
| 5120 | 1.25 ms | 1.28 ms | 2.85 ms | 1.9 MiB | 799 |
| 10240 | 2.45 ms | 2.49 ms | 4.04 ms | 3.8 MiB | 408 |

### `auth.handle (POST /auth/sign-up)`

**Why we benchmark it.** Sign-up is the first state-changing request: it runs the origin check, the form parser, the CSRF verification and the identifier rules before any account exists, so it is the path an unauthenticated client can reach most cheaply.

**What poor performance would mean.** Cost that grows faster than the body would let anonymous clients exhaust the server with large sign-up bodies before rate limiting (phase 4) applies.

**Expected growth: O(1).** The body is parsed in one pass, but at these sizes that pass is dwarfed by fixed work every sign-up does: the CSRF MAC check, creating the account and the session, and issuing a token.

**Measured on a shorter ladder (16, 32, 64, 128, 254).** An identifier longer than 254 characters is refused before any account is created, a different and cheaper path, so the ladder stops at the longest valid address.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| identifier characters | swept | Length of the submitted identifier, every size a valid address. |
| body format | fixed at "form" | URL-encoded, which is what the default pages post. |

**Deliberately not covered**

- **JSON bodies**: The JSON parser is the other branch of the same body reader; the form branch is what the default pages use.

**In the end-to-end run:** Not part of the end-to-end request; measured on its own.

**Measured: O(1)** (exponent -0.03, 5 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 16 | 520 µs | 741 µs | 2.17 ms | 155.7 KiB | 1,922 |
| 32 | 501 µs | 556 µs | 2.13 ms | 155.3 KiB | 1,997 |
| 64 | 509 µs | 576 µs | 2.14 ms | 151.0 KiB | 1,966 |
| 128 | 484 µs | 577 µs | 2.15 ms | 148.2 KiB | 2,067 |
| 254 | 485 µs | 612 µs | 2.17 ms | 150.7 KiB | 2,060 |

### `auth.handle (POST /auth/sign-in)`

**Why we benchmark it.** Every password sign-in runs argon2id, and so does every failed one, an unknown account included, so that a reply's timing never says whether an account exists. It is the most expensive thing test-cap does per request.

**What poor performance would mean.** Sign-in latency users feel directly, and server capacity: argon2id holds memory for each hash, so slow hashing under load queues sign-ins behind the concurrency limit and answers 503 busy.

**Expected growth: O(1).** argon2id's cost is fixed by its memory and iteration parameters; the password is hashed once into its fixed-size input, so its length barely changes the work.

**Measured on a shorter ladder (8, 16, 32, 64, 128, 256).** Passwords are capped at 256 characters (ADR 0010), so longer inputs are refused before hashing and would measure the refusal, not argon2id.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| password characters | swept | Length of the submitted password. |
| hash cost | variant | The test-mode cost the ladder runs at, and the real production cost, measured as the variants below. |
| account | fixed at "unknown" | No account has the identifier, so the dummy hash runs: the same work a known account's check does. |

**Deliberately not covered**

- **concurrent sign-ins**: The concurrency limit makes simultaneous hashes queue; measuring the queue would measure the limit, which ADR 0010 sets, not the hash.

**In the end-to-end run:** Not part of the end-to-end request; measured on its own.

#### Variant `test-cost`

The reduced test-mode argon2id cost (argon2Cost: m=8 KiB, t=1, p=1).

**Measured: O(1)** (exponent -0.02, 6 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 8 | 547 µs | 894 µs | 2.33 ms | 180.3 KiB | 1,828 |
| 16 | 350 µs | 423 µs | 994 µs | 167.7 KiB | 2,855 |
| 32 | 404 µs | 662 µs | 1.32 ms | 169.6 KiB | 2,477 |
| 64 | 328 µs | 397 µs | 980 µs | 168.1 KiB | 3,051 |
| 128 | 338 µs | 450 µs | 1.25 ms | 165.3 KiB | 2,961 |
| 256 | 355 µs | 612 µs | 1.27 ms | 166.7 KiB | 2,820 |

#### Variant `real-cost`

The production argon2id cost ADR 0018 fixes: m=19456 KiB, t=2, p=1.

**Measured: O(1)** (exponent 0.00, 6 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 8 | 32.8 ms | 33.8 ms | 35.1 ms | 169.8 KiB | 30 |
| 16 | 32.8 ms | 33.2 ms | 35.2 ms | 170.0 KiB | 30 |
| 32 | 32.8 ms | 33.0 ms | 35.0 ms | 170.0 KiB | 31 |
| 64 | 32.8 ms | 33.3 ms | 35.0 ms | 170.5 KiB | 30 |
| 128 | 32.8 ms | 34.6 ms | 35.1 ms | 171.2 KiB | 30 |
| 256 | 33.0 ms | 33.5 ms | 35.2 ms | 172.5 KiB | 30 |

### `createAuth`

**Why we benchmark it.** Runs once per process start, and every serverless cold start pays it: it checks the deployment, parses every key ring and wires the store, policy and methods.

**What poor performance would mean.** Slower cold starts on every deploy and every scale-up from zero; a key-ring parser that grew faster than the ring would make key rotation, which adds entries, slow startup down.

**Expected growth: O(n).** Each key-ring entry is split and base64url-decoded once.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| key-ring entries | swept | Entries in each of AUTH_ENCRYPTION_KEY and AUTH_CSRF_KEY. |

**Deliberately not covered**

- **refusal**: A deployment that may not start throws once at startup; its cost is not paid by a running app.

**In the end-to-end run:** Runs once at startup, outside the per-request path.

**Measured: O(n)** (exponent 0.98, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 228 µs | 251 µs | 778 µs | 181.5 KiB | 4,383 |
| 40 | 424 µs | 447 µs | 1.35 ms | 338.0 KiB | 2,360 |
| 80 | 838 µs | 867 µs | 2.23 ms | 652.8 KiB | 1,193 |
| 160 | 1.68 ms | 1.76 ms | 4.44 ms | 1.3 MiB | 594 |
| 320 | 3.21 ms | 3.31 ms | 5.95 ms | 2.5 MiB | 312 |
| 640 | 6.27 ms | 6.38 ms | 9.14 ms | 5.0 MiB | 160 |
| 1280 | 12.1 ms | 12.4 ms | 14.9 ms | 9.8 MiB | 82 |
| 2560 | 24.1 ms | 24.2 ms | 27.6 ms | 19.7 MiB | 42 |
| 5120 | 47.1 ms | 48.9 ms | 56.2 ms | 38.1 MiB | 21 |
| 10240 | 94.3 ms | 95.3 ms | 108 ms | 15.8 MiB | 11 |

### `defineAuthPolicy`

**Why we benchmark it.** Runs once at startup over every requirement id the app (or access-cap) maps; a large app may define hundreds.

**What poor performance would mean.** Slower cold starts for apps with many requirements.

**Expected growth: O(n).** Each requirement is validated once and stored in a map.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| requirements | swept | Requirement ids in the policy. |

**Deliberately not covered**

- **trust configuration**: OIDC issuer trust arrives in phase 5; phase 3 has no issuer to configure.

**In the end-to-end run:** Runs once at startup, outside the per-request path.

**Measured: O(n log n)** (exponent 1.30, 10 sizes): 🟡 close (neighbouring class).

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 4.59 µs | 9.25 µs | 4.68 µs | 10.0 KiB | 217,968 |
| 40 | 8.35 µs | 11.5 µs | 8.59 µs | 17.1 KiB | 119,823 |
| 80 | 12.9 µs | 13.2 µs | 47.6 µs | 17.9 KiB | 77,579 |
| 160 | 25.3 µs | 26.5 µs | 81.1 µs | 33.2 KiB | 39,463 |
| 320 | 50.5 µs | 51.5 µs | 155 µs | 63.3 KiB | 19,797 |
| 640 | 99.1 µs | 101 µs | 296 µs | 123.8 KiB | 10,086 |
| 1280 | 362 µs | 400 µs | 1.04 ms | 337.9 KiB | 2,763 |
| 2560 | 762 µs | 854 µs | 1.80 ms | 705.5 KiB | 1,312 |
| 5120 | 1.86 ms | 1.96 ms | 4.01 ms | 1.3 MiB | 538 |
| 10240 | 3.98 ms | 4.10 ms | 6.25 ms | 2.6 MiB | 251 |

### `expressAuth`

**Why we benchmark it.** The middleware sits in front of every route of an Express app; each request outside /auth/ is matched against the public list before the app sees it.

**What poor performance would mean.** Every request to the app pays the matching cost; an app with a long public list would slow down all of its traffic, not only sign-in.

**Expected growth: O(n).** Exact entries are a set lookup, but each wildcard entry is a prefix test, and a path that matches the last one is tested against all of them.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| public wildcard entries | swept | Entries such as /docs0/* in the public list; the request matches the last. |

**Deliberately not covered**

- **protected routes**: A protected route adds the session read, which the session benchmark measures.

**In the end-to-end run:** Adapter cost, outside the core request measured end to end.

**Measured: O(n)** (exponent 0.75, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 4.03 µs | 5.81 µs | 4.53 µs | 4.0 KiB | 247,934 |
| 40 | 3.74 µs | 4.10 µs | 3.80 µs | 3.8 KiB | 267,682 |
| 80 | 5.34 µs | 5.81 µs | 5.43 µs | 3.8 KiB | 187,406 |
| 160 | 9.43 µs | 9.76 µs | 9.49 µs | 3.4 KiB | 106,068 |
| 320 | 16.3 µs | 16.7 µs | 16.4 µs | 3.4 KiB | 61,198 |
| 640 | 28.2 µs | 30.6 µs | 123 µs | 3.5 KiB | 35,420 |
| 1280 | 59.4 µs | 62.5 µs | 227 µs | 3.6 KiB | 16,839 |
| 2560 | 114 µs | 121 µs | 388 µs | 3.6 KiB | 8,772 |
| 5120 | 129 µs | 134 µs | 460 µs | 3.6 KiB | 7,779 |
| 10240 | 259 µs | 271 µs | 913 µs | 3.9 KiB | 3,862 |

### `expressAuth (per request)`

**Why we benchmark it.** The middleware sits in front of every route of an Express app, so every request pays it: the raw header lines turned into Headers, the path match, and under /auth/ the raw body read and the reply written to Node's response. Each request is a real Node IncomingMessage and ServerResponse over a socket that discards its writes, so Node's own header serialization is in the figure and the network is not.

**What poor performance would mean.** A tax on all of the app's traffic, public pages included: slower responses and more servers for the same load. Cost that grew with the number of requests served would mean the middleware keeps something per request, and a long-running process would slow down until it restarts.

**Expected growth: O(n).** Each request does the same fixed work: one header conversion, one path match and at most one call into the core, so n requests cost n times one.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| requests | swept | The tier axis: requests sent through the returned handler, one after another. |
| route | variant | The session request, a public page and a protected page, as the variants below. |
| session | fixed at "none" | No request carries a session cookie, so no request reads a session from the store. |

**Deliberately not covered**

- **a signed-in request**: A live session adds auth.require's store read and assurance check, which auth-require measures; the adapter's own work, the conversion and the path match, does not change.
- **a request body**: Every request here is a GET. A body under /auth/ is read once, capped at the core's 64 KiB limit, and sign-up-body measures a body through auth.handle.
- **concurrent requests**: The returned handler keeps no state between requests, so requests in parallel would measure the event loop, not the adapter.

**In the end-to-end run:** Adapter cost, outside the core request measured end to end.

#### Variant `auth-route`

GET /auth/session, the request every page load makes first: served by auth.handle, and the reply converted back.

**Measured: O(n)** (exponent 0.97, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 1.46 ms | 1.97 ms | 3.64 ms | 784.5 KiB | 685 |
| 40 | 2.47 ms | 2.82 ms | 4.82 ms | 1.4 MiB | 405 |
| 80 | 4.54 ms | 5.21 ms | 6.75 ms | 2.8 MiB | 220 |
| 160 | 8.94 ms | 9.81 ms | 13.0 ms | 5.5 MiB | 112 |
| 320 | 16.9 ms | 19.3 ms | 20.6 ms | 10.9 MiB | 59 |
| 640 | 34.1 ms | 36.4 ms | 44.8 ms | 21.7 MiB | 29 |
| 1280 | 65.5 ms | 70.9 ms | 85.2 ms | 43.0 MiB | 15 |
| 2560 | 131 ms | 136 ms | 170 ms | 39.0 MiB | 8 |
| 5120 | 251 ms | 255 ms | 327 ms | 38.0 MiB | 4 |
| 10240 | 504 ms | 543 ms | 654 ms | 76.1 MiB | 2 |

#### Variant `public-route`

GET /, on the public list: the path match hands it to the app without reading a session.

**Measured: O(n)** (exponent 1.00, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 28.5 µs | 39.4 µs | 35.0 µs | 59.9 KiB | 35,140 |
| 40 | 46.8 µs | 66.5 µs | 55.0 µs | 117.9 KiB | 21,372 |
| 80 | 82.0 µs | 86.4 µs | 87.0 µs | 234.4 KiB | 12,195 |
| 160 | 156 µs | 180 µs | 164 µs | 467.6 KiB | 6,422 |
| 320 | 304 µs | 371 µs | 328 µs | 934.3 KiB | 3,293 |
| 640 | 604 µs | 694 µs | 644 µs | 1.8 MiB | 1,655 |
| 1280 | 1.20 ms | 1.25 ms | 1.80 ms | 3.6 MiB | 831 |
| 2560 | 2.39 ms | 5.40 ms | 7.59 ms | 7.3 MiB | 418 |
| 5120 | 4.81 ms | 5.20 ms | 12.1 ms | 14.6 MiB | 208 |
| 10240 | 9.63 ms | 9.81 ms | 29.2 ms | 29.2 MiB | 104 |

#### Variant `protected-route`

GET /account with no session: deny by default refuses it with a 401 the adapter converts back.

**Measured: O(n)** (exponent 0.88, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 465 µs | 564 µs | 530 µs | 324.0 KiB | 2,153 |
| 40 | 828 µs | 932 µs | 2.25 ms | 639.8 KiB | 1,208 |
| 80 | 1.56 ms | 1.68 ms | 5.23 ms | 1.2 MiB | 640 |
| 160 | 2.90 ms | 3.23 ms | 10.5 ms | 2.5 MiB | 345 |
| 320 | 5.52 ms | 5.79 ms | 13.8 ms | 5.0 MiB | 181 |
| 640 | 10.5 ms | 11.0 ms | 19.4 ms | 9.9 MiB | 95 |
| 1280 | 20.1 ms | 21.1 ms | 30.5 ms | 19.8 MiB | 50 |
| 2560 | 34.7 ms | 37.5 ms | 51.5 ms | 39.7 MiB | 29 |
| 5120 | 66.2 ms | 67.7 ms | 101 ms | 21.0 MiB | 15 |
| 10240 | 121 ms | 124 ms | 188 ms | 45.9 MiB | 8 |

### `withAuth`

**Why we benchmark it.** withAuth wraps the whole app on Bun, Deno and any server that hands over a Web Request, so every request pays it: the head converted to test-cap's request, the path match, and under /auth/ the reply converted to a Response with each cookie on its own line. The requests are Web Requests built ahead, so the runtime's own parsing stays out of the figure.

**What poor performance would mean.** A tax on all of the app's traffic, public pages included: slower responses and more servers for the same load. Cost that grew with the number of requests served would mean the wrapper keeps something per request.

**Expected growth: O(n).** Each request does the same fixed work: one head conversion, one path match and at most one call into the core, so n requests cost n times one.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| requests | swept | The tier axis: requests sent through the returned handler, one after another. |
| route | variant | The session request, a public page and a protected page, as the variants below. |
| session | fixed at "none" | No request carries a session cookie, so no request reads a session from the store. |

**Deliberately not covered**

- **a signed-in request**: A live session adds auth.require's store read and assurance check, which auth-require measures; the adapter's own work, the conversion and the path match, does not change.
- **a request body**: Every request here is a GET. A body under /auth/ is read once, capped at the core's 64 KiB limit, and sign-up-body measures a body through auth.handle.
- **concurrent requests**: The returned handler keeps no state between requests, so requests in parallel would measure the event loop, not the adapter.

**In the end-to-end run:** Adapter cost, outside the core request measured end to end.

#### Variant `auth-route`

GET /auth/session, the request every page load makes first: served by auth.handle, and the reply converted back.

**Measured: O(n)** (exponent 0.97, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 1.38 ms | 1.70 ms | 3.46 ms | 742.8 KiB | 726 |
| 40 | 2.21 ms | 2.32 ms | 4.18 ms | 1.4 MiB | 452 |
| 80 | 4.01 ms | 4.24 ms | 6.01 ms | 2.8 MiB | 249 |
| 160 | 7.96 ms | 8.31 ms | 11.2 ms | 5.6 MiB | 126 |
| 320 | 15.3 ms | 16.1 ms | 23.0 ms | 11.0 MiB | 65 |
| 640 | 30.2 ms | 32.4 ms | 39.8 ms | 22.1 MiB | 33 |
| 1280 | 59.9 ms | 60.3 ms | 71.9 ms | 44.0 MiB | 17 |
| 2560 | 117 ms | 118 ms | 134 ms | 36.6 MiB | 9 |
| 5120 | 228 ms | 242 ms | 264 ms | 21.0 MiB | 4 |
| 10240 | 439 ms | 473 ms | 486 ms | 39.7 MiB | 2 |

#### Variant `public-route`

GET /, on the public list: the path match hands it to the app without reading a session.

**Measured: O(n)** (exponent 1.01, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 15.2 µs | 17.3 µs | 15.4 µs | 48.3 KiB | 65,865 |
| 40 | 27.0 µs | 31.0 µs | 92.4 µs | 95.3 KiB | 37,056 |
| 80 | 55.7 µs | 83.6 µs | 177 µs | 189.4 KiB | 17,937 |
| 160 | 107 µs | 136 µs | 431 µs | 377.7 KiB | 9,382 |
| 320 | 213 µs | 219 µs | 618 µs | 754.0 KiB | 4,703 |
| 640 | 429 µs | 503 µs | 1.47 ms | 1.5 MiB | 2,333 |
| 1280 | 853 µs | 895 µs | 1.95 ms | 2.9 MiB | 1,173 |
| 2560 | 1.72 ms | 1.75 ms | 4.15 ms | 5.9 MiB | 582 |
| 5120 | 3.48 ms | 3.66 ms | 6.44 ms | 11.8 MiB | 287 |
| 10240 | 7.12 ms | 7.30 ms | 11.2 ms | 23.5 MiB | 140 |

#### Variant `protected-route`

GET /account with no session: deny by default refuses it with a 401 the adapter converts back.

**Measured: O(n)** (exponent 0.94, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 296 µs | 336 µs | 1.02 ms | 363.5 KiB | 3,373 |
| 40 | 574 µs | 636 µs | 1.83 ms | 724.8 KiB | 1,741 |
| 80 | 1.21 ms | 1.59 ms | 3.82 ms | 1.4 MiB | 823 |
| 160 | 2.28 ms | 2.39 ms | 6.19 ms | 2.8 MiB | 439 |
| 320 | 4.45 ms | 4.63 ms | 11.0 ms | 5.6 MiB | 225 |
| 640 | 8.63 ms | 9.04 ms | 15.8 ms | 11.2 MiB | 116 |
| 1280 | 17.4 ms | 18.8 ms | 26.6 ms | 22.4 MiB | 57 |
| 2560 | 31.6 ms | 33.5 ms | 42.9 ms | 44.6 MiB | 32 |
| 5120 | 61.1 ms | 62.7 ms | 76.9 ms | 24.8 MiB | 16 |
| 10240 | 118 ms | 148 ms | 144 ms | 48.2 MiB | 8 |

### `fetchAuth`

**Why we benchmark it.** An app that routes by itself on Bun or Deno hands every request to fetchAuth first, so each pays the check for /auth/, and the session request every page load makes also pays the conversion both ways. The requests are Web Requests built ahead, so the runtime's own parsing stays out of the figure.

**What poor performance would mean.** Slower responses on every route of the app, since each request is offered to fetchAuth before the app's own router sees it.

**Expected growth: O(n).** Each request does the same fixed work: one path check and, under /auth/, one conversion each way and one call into the core, so n requests cost n times one.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| requests | swept | The tier axis: requests sent through the returned handler, one after another. |
| route | variant | A path under /auth/ and one outside it, as the variants below. |
| session | fixed at "none" | No request carries a session cookie, so no request reads a session from the store. |

**Deliberately not covered**

- **a request body**: Every request here is a GET. A body under /auth/ is read once, capped at the core's 64 KiB limit, and sign-up-body measures a body through auth.handle.
- **concurrent requests**: The returned handler keeps no state between requests, so requests in parallel would measure the event loop, not the adapter.

**In the end-to-end run:** Adapter cost, outside the core request measured end to end.

#### Variant `auth-route`

GET /auth/session, the request every page load makes first: served by auth.handle, and the reply converted back.

**Measured: O(n)** (exponent 0.98, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 1.10 ms | 1.59 ms | 3.59 ms | 684.3 KiB | 913 |
| 40 | 1.99 ms | 2.61 ms | 4.15 ms | 1.3 MiB | 501 |
| 80 | 3.96 ms | 4.31 ms | 7.02 ms | 2.6 MiB | 252 |
| 160 | 7.63 ms | 7.89 ms | 13.6 ms | 5.3 MiB | 131 |
| 320 | 14.8 ms | 15.0 ms | 21.1 ms | 10.6 MiB | 67 |
| 640 | 29.3 ms | 29.8 ms | 36.7 ms | 21.1 MiB | 34 |
| 1280 | 58.1 ms | 61.3 ms | 69.1 ms | 42.1 MiB | 17 |
| 2560 | 114 ms | 116 ms | 132 ms | 32.9 MiB | 9 |
| 5120 | 225 ms | 233 ms | 261 ms | 13.8 MiB | 4 |
| 10240 | 438 ms | 440 ms | 482 ms | 25.2 MiB | 2 |

#### Variant `outside-auth`

GET /account: answered null with the body unread, for the app's own router.

**Measured: O(n)** (exponent 1.02, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 12.6 µs | 18.8 µs | 12.8 µs | 36.1 KiB | 79,228 |
| 40 | 28.0 µs | 33.9 µs | 113 µs | 71.0 KiB | 35,722 |
| 80 | 47.9 µs | 55.4 µs | 173 µs | 140.7 KiB | 20,863 |
| 160 | 93.9 µs | 96.8 µs | 275 µs | 280.1 KiB | 10,648 |
| 320 | 187 µs | 190 µs | 525 µs | 559.0 KiB | 5,341 |
| 640 | 370 µs | 377 µs | 1.07 ms | 1.1 MiB | 2,700 |
| 1280 | 744 µs | 777 µs | 1.86 ms | 2.2 MiB | 1,343 |
| 2560 | 1.52 ms | 1.66 ms | 3.97 ms | 4.4 MiB | 658 |
| 5120 | 3.07 ms | 3.27 ms | 6.06 ms | 8.7 MiB | 326 |
| 10240 | 6.22 ms | 6.57 ms | 10.3 ms | 17.4 MiB | 161 |

### `nextAuthHandler`

**Why we benchmark it.** The route handler for app/auth/[...path]/route.ts serves every /auth/ request a Next.js app receives, the session request every page load makes included. Next.js hands it a Web Request, built ahead here, and it converts through test-cap/fetch.

**What poor performance would mean.** Slower page loads, since each one waits on the session request, and more server time per visitor.

**Expected growth: O(n).** Each request does the same fixed work: one path check, one conversion each way and one call into the core, so n requests cost n times one.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| requests | swept | The tier axis: requests sent through the returned handler, one after another. |
| route | fixed at "GET /auth/session" | The request every page load makes first, through the GET handler. |
| session | fixed at "none" | No request carries a session cookie, so no request reads a session from the store. |

**Deliberately not covered**

- **the POST handler**: POST is the same function as GET; a POST adds the body read, which sign-up-body measures through auth.handle.
- **concurrent requests**: The returned handler keeps no state between requests, so requests in parallel would measure the event loop, not the adapter.

**In the end-to-end run:** Adapter cost, outside the core request measured end to end.

**Measured: O(n)** (exponent 0.97, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 1.30 ms | 1.54 ms | 3.57 ms | 696.9 KiB | 771 |
| 40 | 2.04 ms | 2.81 ms | 4.36 ms | 1.4 MiB | 490 |
| 80 | 4.00 ms | 4.40 ms | 7.07 ms | 2.7 MiB | 250 |
| 160 | 7.73 ms | 8.00 ms | 13.9 ms | 5.4 MiB | 129 |
| 320 | 15.0 ms | 16.9 ms | 22.0 ms | 10.8 MiB | 66 |
| 640 | 29.6 ms | 30.2 ms | 38.8 ms | 21.5 MiB | 34 |
| 1280 | 58.1 ms | 59.7 ms | 70.0 ms | 42.9 MiB | 17 |
| 2560 | 116 ms | 119 ms | 132 ms | 34.5 MiB | 9 |
| 5120 | 225 ms | 234 ms | 262 ms | 17.3 MiB | 4 |
| 10240 | 436 ms | 439 ms | 482 ms | 31.8 MiB | 2 |

### `nextProxy`

**Why we benchmark it.** A Next.js proxy runs before every route its matcher covers, so its cost lands on more requests than any other surface. It never reads the store: it matches the path, looks for a session cookie and builds a redirect.

**What poor performance would mean.** Every page and every matched request waits on it, so a slow proxy slows the whole app, including pages that need no session.

**Expected growth: O(n).** Each request does the same fixed work: one path check, one URL parse, one cookie scan and at most one redirect, so n requests cost n times one.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| requests | swept | The tier axis: requests sent through the returned handler, one after another. |
| route | variant | A public page, a protected page without a session cookie and one with a cookie, as the variants below. |

**Deliberately not covered**

- **concurrent requests**: The returned handler keeps no state between requests, so requests in parallel would measure the event loop, not the adapter.

**In the end-to-end run:** Adapter cost, outside the core request measured end to end.

#### Variant `public-route`

GET /, on the public list: the path match hands it to the app without reading a session.

**Measured: O(n)** (exponent 1.01, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 9.72 µs | 11.5 µs | 9.96 µs | 16.8 KiB | 102,857 |
| 40 | 18.3 µs | 21.3 µs | 74.4 µs | 31.3 KiB | 54,549 |
| 80 | 36.3 µs | 49.2 µs | 140 µs | 60.7 KiB | 27,564 |
| 160 | 73.6 µs | 99.1 µs | 279 µs | 120.8 KiB | 13,588 |
| 320 | 144 µs | 148 µs | 435 µs | 240.8 KiB | 6,946 |
| 640 | 291 µs | 301 µs | 818 µs | 480.9 KiB | 3,442 |
| 1280 | 590 µs | 658 µs | 1.71 ms | 961.0 KiB | 1,694 |
| 2560 | 1.18 ms | 1.21 ms | 3.63 ms | 1.9 MiB | 850 |
| 5120 | 2.38 ms | 2.69 ms | 5.43 ms | 3.8 MiB | 420 |
| 10240 | 4.81 ms | 4.96 ms | 8.82 ms | 7.5 MiB | 208 |

#### Variant `redirect`

GET /account with no session cookie: a 307 to the sign-in page, built on APP_ORIGIN.

**Measured: O(n)** (exponent 0.98, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 46.3 µs | 51.1 µs | 195 µs | 52.5 KiB | 21,617 |
| 40 | 91.0 µs | 94.7 µs | 286 µs | 104.2 KiB | 10,984 |
| 80 | 181 µs | 189 µs | 507 µs | 207.5 KiB | 5,528 |
| 160 | 360 µs | 365 µs | 1.02 ms | 414.4 KiB | 2,777 |
| 320 | 717 µs | 745 µs | 1.75 ms | 827.5 KiB | 1,394 |
| 640 | 1.44 ms | 1.47 ms | 3.53 ms | 1.6 MiB | 694 |
| 1280 | 2.86 ms | 2.93 ms | 5.14 ms | 3.2 MiB | 350 |
| 2560 | 5.72 ms | 5.92 ms | 8.36 ms | 6.5 MiB | 175 |
| 5120 | 11.1 ms | 33.0 ms | 14.5 ms | 12.9 MiB | 90 |
| 10240 | 22.0 ms | 23.1 ms | 26.5 ms | 25.8 MiB | 45 |

#### Variant `session-cookie`

GET /account with a session cookie: the proxy lets it continue without reading the store.

**Measured: O(n)** (exponent 1.00, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 20.8 µs | 22.0 µs | 79.4 µs | 30.4 KiB | 47,994 |
| 40 | 40.7 µs | 46.8 µs | 136 µs | 60.1 KiB | 24,561 |
| 80 | 80.6 µs | 82.4 µs | 248 µs | 119.5 KiB | 12,407 |
| 160 | 162 µs | 167 µs | 452 µs | 238.3 KiB | 6,190 |
| 320 | 321 µs | 334 µs | 835 µs | 475.8 KiB | 3,114 |
| 640 | 640 µs | 699 µs | 1.71 ms | 951.0 KiB | 1,562 |
| 1280 | 1.29 ms | 1.32 ms | 3.53 ms | 1.9 MiB | 777 |
| 2560 | 2.58 ms | 2.69 ms | 5.11 ms | 3.7 MiB | 388 |
| 5120 | 5.12 ms | 5.23 ms | 8.24 ms | 7.4 MiB | 195 |
| 10240 | 10.1 ms | 10.2 ms | 14.3 ms | 14.9 MiB | 99 |

### `nextServerAuth`

**Why we benchmark it.** The authoritative check of a Next.js app: route handlers, server functions and the data-access layer call it whenever they need a session, often several times per request. Each call copies the request's headers from next/headers into test-cap's request before the core reads the cookie.

**What poor performance would mean.** Every protected read pays it, sometimes several times per request, so a slow helper slows every page and action that touches data.

**Expected growth: O(n).** Each call does the same fixed work: one copy of the request's few headers and one call into the core, so n calls cost n times one.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| requests | swept | The tier axis: requests sent through the returned handler, one after another. |
| helper | variant | session() and require(), as the variants below. |
| session | fixed at "none" | No request carries a session cookie, so no request reads a session from the store. |

**Deliberately not covered**

- **a signed-in request**: A live session adds auth.require's store read and assurance check, which auth-require measures; the adapter's own work, the conversion and the path match, does not change.
- **concurrent requests**: The returned handler keeps no state between requests, so requests in parallel would measure the event loop, not the adapter.

**In the end-to-end run:** Adapter cost, outside the core request measured end to end.

#### Variant `session`

serverAuth.session() with no session cookie: answers null.

**Measured: O(n)** (exponent 1.00, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 24.6 µs | 27.5 µs | 26.3 µs | 73.3 KiB | 40,602 |
| 40 | 46.1 µs | 55.0 µs | 198 µs | 146.1 KiB | 21,689 |
| 80 | 91.8 µs | 93.8 µs | 272 µs | 291.4 KiB | 10,893 |
| 160 | 184 µs | 207 µs | 515 µs | 582.2 KiB | 5,446 |
| 320 | 367 µs | 370 µs | 1.03 ms | 1.1 MiB | 2,727 |
| 640 | 732 µs | 741 µs | 1.72 ms | 2.3 MiB | 1,366 |
| 1280 | 1.47 ms | 1.48 ms | 3.44 ms | 4.5 MiB | 682 |
| 2560 | 2.94 ms | 2.97 ms | 4.92 ms | 9.1 MiB | 340 |
| 5120 | 5.87 ms | 5.92 ms | 7.84 ms | 18.2 MiB | 170 |
| 10240 | 11.7 ms | 11.8 ms | 13.7 ms | 36.3 MiB | 85 |

#### Variant `require`

serverAuth.require() at the default requirement with no session cookie: answers unauthenticated.

**Measured: O(n)** (exponent 1.00, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 25.2 µs | 27.7 µs | 104 µs | 78.9 KiB | 39,725 |
| 40 | 49.6 µs | 52.6 µs | 173 µs | 149.1 KiB | 20,143 |
| 80 | 98.7 µs | 99.5 µs | 295 µs | 297.7 KiB | 10,130 |
| 160 | 197 µs | 206 µs | 526 µs | 594.9 KiB | 5,068 |
| 320 | 393 µs | 398 µs | 1.05 ms | 1.2 MiB | 2,542 |
| 640 | 786 µs | 796 µs | 1.77 ms | 2.3 MiB | 1,272 |
| 1280 | 1.57 ms | 1.60 ms | 3.54 ms | 4.6 MiB | 635 |
| 2560 | 3.14 ms | 3.17 ms | 5.14 ms | 9.3 MiB | 318 |
| 5120 | 6.30 ms | 6.36 ms | 8.30 ms | 18.6 MiB | 159 |
| 10240 | 12.6 ms | 23.8 ms | 14.7 ms | 37.1 MiB | 79 |

### `tanstackStartAuth`

**Why we benchmark it.** Its route handler serves the /auth/$ server route, which every page load reaches for the session, and its session and require helpers run inside server functions next to the data. Each converts a Web Request, built ahead here, to test-cap's request; the route handler also converts the reply back.

**What poor performance would mean.** Slower page loads, which wait on the session request, and slower server functions, which call the helpers before touching data.

**Expected growth: O(n).** Each request does the same fixed work: one head conversion, one call into the core and, for the route handler, one conversion back, so n requests cost n times one.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| requests | swept | The tier axis: requests sent through the returned handler, one after another. |
| surface | variant | The route handler and the two helpers, as the variants below. |
| session | fixed at "none" | No request carries a session cookie, so no request reads a session from the store. |

**Deliberately not covered**

- **a signed-in request**: A live session adds auth.require's store read and assurance check, which auth-require measures; the adapter's own work, the conversion and the path match, does not change.
- **a request body**: Every request here is a GET. A body under /auth/ is read once, capped at the core's 64 KiB limit, and sign-up-body measures a body through auth.handle.
- **concurrent requests**: The returned handler keeps no state between requests, so requests in parallel would measure the event loop, not the adapter.

**In the end-to-end run:** Adapter cost, outside the core request measured end to end.

#### Variant `route-handler`

handlers.ANY with GET /auth/session, served by auth.handle.

**Measured: O(n)** (exponent 0.94, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 1.28 ms | 1.68 ms | 3.63 ms | 689.7 KiB | 779 |
| 40 | 2.19 ms | 2.74 ms | 4.34 ms | 1.3 MiB | 458 |
| 80 | 3.91 ms | 4.12 ms | 6.96 ms | 2.7 MiB | 256 |
| 160 | 7.67 ms | 8.86 ms | 14.0 ms | 5.3 MiB | 130 |
| 320 | 15.0 ms | 16.1 ms | 21.9 ms | 10.7 MiB | 67 |
| 640 | 30.9 ms | 35.6 ms | 39.5 ms | 21.3 MiB | 32 |
| 1280 | 67.8 ms | 95.9 ms | 77.0 ms | 42.5 MiB | 15 |
| 2560 | 116 ms | 117 ms | 133 ms | 33.7 MiB | 9 |
| 5120 | 229 ms | 233 ms | 262 ms | 15.3 MiB | 4 |
| 10240 | 438 ms | 469 ms | 482 ms | 27.8 MiB | 2 |

#### Variant `session`

session(request) with no session cookie: answers null.

**Measured: O(n)** (exponent 0.95, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 9.42 µs | 11.4 µs | 9.68 µs | 34.7 KiB | 106,173 |
| 40 | 19.3 µs | 21.4 µs | 73.6 µs | 76.9 KiB | 51,893 |
| 80 | 37.9 µs | 40.9 µs | 118 µs | 153.2 KiB | 26,382 |
| 160 | 75.5 µs | 81.6 µs | 235 µs | 305.8 KiB | 13,250 |
| 320 | 150 µs | 164 µs | 443 µs | 610.9 KiB | 6,664 |
| 640 | 301 µs | 345 µs | 834 µs | 1.2 MiB | 3,319 |
| 1280 | 840 µs | 929 µs | 2.30 ms | 2.4 MiB | 1,190 |
| 2560 | 1.23 ms | 1.47 ms | 3.73 ms | 4.8 MiB | 815 |
| 5120 | 2.43 ms | 2.53 ms | 5.40 ms | 9.5 MiB | 411 |
| 10240 | 4.84 ms | 4.93 ms | 8.95 ms | 19.1 MiB | 207 |

#### Variant `require`

require(request, "default") with no session cookie: answers unauthenticated.

**Measured: O(n)** (exponent 1.00, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 10.7 µs | 11.7 µs | 46.9 µs | 38.9 KiB | 93,326 |
| 40 | 21.1 µs | 23.0 µs | 81.5 µs | 71.9 KiB | 47,454 |
| 80 | 41.7 µs | 42.2 µs | 128 µs | 143.2 KiB | 23,987 |
| 160 | 83.8 µs | 86.5 µs | 253 µs | 285.7 KiB | 11,937 |
| 320 | 166 µs | 175 µs | 510 µs | 570.8 KiB | 6,016 |
| 640 | 332 µs | 338 µs | 1.03 ms | 1.1 MiB | 3,010 |
| 1280 | 672 µs | 687 µs | 1.79 ms | 2.2 MiB | 1,488 |
| 2560 | 1.35 ms | 1.37 ms | 3.81 ms | 4.5 MiB | 741 |
| 5120 | 2.70 ms | 2.78 ms | 5.66 ms | 8.9 MiB | 371 |
| 10240 | 5.37 ms | 5.44 ms | 9.32 ms | 17.8 MiB | 186 |

### `tanstackStartMiddleware`

**Why we benchmark it.** Registered as a global request middleware, it runs on every request a TanStack Start app receives: pages, server routes and server function calls. Each pays the head conversion and the path match before the app runs. The requests are Web Requests built ahead, so the framework's own work stays out of the figure.

**What poor performance would mean.** A tax on all of the app's traffic, public pages and server function calls included: slower responses and more servers for the same load.

**Expected growth: O(n).** Each request does the same fixed work: one head conversion and one path match, plus a refusal converted back when deny by default refuses it, so n requests cost n times one.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| requests | swept | The tier axis: requests sent through the returned handler, one after another. |
| route | variant | The session request, a public page and a protected page, as the variants below. |
| session | fixed at "none" | No request carries a session cookie, so no request reads a session from the store. |

**Deliberately not covered**

- **a signed-in request**: A live session adds auth.require's store read and assurance check, which auth-require measures; the adapter's own work, the conversion and the path match, does not change.
- **concurrent requests**: The returned handler keeps no state between requests, so requests in parallel would measure the event loop, not the adapter.

**In the end-to-end run:** Adapter cost, outside the core request measured end to end.

#### Variant `auth-route`

GET /auth/session: handed on to the /auth/$ server route, which tanstack-start-auth measures.

**Measured: O(n)** (exponent 1.01, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 17.6 µs | 19.1 µs | 82.4 µs | 44.8 KiB | 56,664 |
| 40 | 33.4 µs | 38.6 µs | 124 µs | 93.6 KiB | 29,925 |
| 80 | 66.7 µs | 67.8 µs | 200 µs | 186.4 KiB | 15,001 |
| 160 | 133 µs | 136 µs | 386 µs | 372.1 KiB | 7,531 |
| 320 | 265 µs | 270 µs | 775 µs | 743.4 KiB | 3,777 |
| 640 | 532 µs | 560 µs | 1.60 ms | 1.5 MiB | 1,880 |
| 1280 | 1.07 ms | 1.09 ms | 3.30 ms | 2.9 MiB | 932 |
| 2560 | 2.17 ms | 2.37 ms | 4.79 ms | 5.8 MiB | 461 |
| 5120 | 4.35 ms | 4.51 ms | 7.41 ms | 11.6 MiB | 230 |
| 10240 | 8.82 ms | 9.04 ms | 12.9 ms | 23.1 MiB | 113 |

#### Variant `public-route`

GET /, on the public list: the path match hands it to the app without reading a session.

**Measured: O(n)** (exponent 1.06, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 12.8 µs | 13.2 µs | 54.9 µs | 45.1 KiB | 78,219 |
| 40 | 24.5 µs | 24.8 µs | 79.8 µs | 89.5 KiB | 40,780 |
| 80 | 48.9 µs | 51.5 µs | 156 µs | 178.3 KiB | 20,466 |
| 160 | 97.6 µs | 100 µs | 283 µs | 355.9 KiB | 10,244 |
| 320 | 196 µs | 199 µs | 542 µs | 711.0 KiB | 5,096 |
| 640 | 390 µs | 415 µs | 1.10 ms | 1.4 MiB | 2,567 |
| 1280 | 786 µs | 804 µs | 1.92 ms | 2.8 MiB | 1,272 |
| 2560 | 1.59 ms | 1.67 ms | 4.12 ms | 5.5 MiB | 628 |
| 5120 | 3.49 ms | 4.02 ms | 6.69 ms | 11.1 MiB | 286 |
| 10240 | 7.20 ms | 12.9 ms | 11.7 ms | 22.1 MiB | 139 |

#### Variant `protected-route`

GET /account with no session: deny by default refuses it with a 401 the adapter converts back.

**Measured: O(n)** (exponent 0.93, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 314 µs | 724 µs | 1.17 ms | 354.2 KiB | 3,183 |
| 40 | 637 µs | 760 µs | 1.03 ms | 709.2 KiB | 1,570 |
| 80 | 1.13 ms | 1.21 ms | 3.64 ms | 1.4 MiB | 887 |
| 160 | 2.24 ms | 2.51 ms | 5.89 ms | 2.8 MiB | 447 |
| 320 | 4.43 ms | 6.18 ms | 10.1 ms | 5.5 MiB | 226 |
| 640 | 8.86 ms | 9.53 ms | 15.4 ms | 11.1 MiB | 113 |
| 1280 | 16.7 ms | 17.4 ms | 24.4 ms | 22.0 MiB | 60 |
| 2560 | 32.0 ms | 34.1 ms | 42.4 ms | 43.9 MiB | 31 |
| 5120 | 60.5 ms | 63.8 ms | 75.6 ms | 23.3 MiB | 17 |
| 10240 | 118 ms | 119 ms | 144 ms | 45.2 MiB | 8 |

### `auth.handle (POST /auth/totp/verify)`

**Why we benchmark it.** Every password sign-in at the default AAL2 ends with a TOTP code, and so does a TOTP step-up, so this runs on nearly every sign-in. It tries each of the account's TOTP authenticators in turn: a decryption and up to three HMACs each.

**What poor performance would mean.** Slower second-factor checks for every user, worst for the people with several authenticator apps; a wrong code always pays for every authenticator.

**Expected growth: O(n).** verifyTotp lists the account's authenticators and tries each until one accepts, so the work grows with how many the account holds.

**Measured on a shorter ladder (1, 2, 3, 4, 5).** An account holds at most five TOTP authenticators, so the ladder is every count it can have.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| authenticators | swept | Confirmed TOTP authenticators on the account. |
| outcome | variant | A code from the newest authenticator (the last one tried) or a wrong code, as the variants below. |

**Deliberately not covered**

- **replay**: A replayed time step is refused by the same per-authenticator loop, after the same work.

**In the end-to-end run:** Runs once per sign-in, not on every request.

#### Variant `newest-matches`

The code is the newest authenticator's: every earlier one is tried first.

**Measured: O(log n)** (exponent 0.33, 5 sizes): 🟡 close (neighbouring class).

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 1 | 975 µs | 1.22 ms | 3.19 ms | 303.3 KiB | 1,026 |
| 2 | 1.14 ms | 1.22 ms | 3.31 ms | 380.3 KiB | 878 |
| 3 | 1.32 ms | 1.40 ms | 3.51 ms | 437.4 KiB | 757 |
| 4 | 1.48 ms | 1.57 ms | 3.67 ms | 511.2 KiB | 675 |
| 5 | 1.67 ms | 1.92 ms | 3.83 ms | 589.5 KiB | 597 |

#### Variant `wrong-code`

A code no authenticator accepts: every one is tried.

**Measured: O(log n)** (exponent 0.46, 5 sizes): 🟡 close (neighbouring class).

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 1 | 640 µs | 849 µs | 2.83 ms | 162.6 KiB | 1,563 |
| 2 | 898 µs | 1.01 ms | 3.11 ms | 238.3 KiB | 1,114 |
| 3 | 1.06 ms | 1.22 ms | 3.23 ms | 312.9 KiB | 946 |
| 4 | 1.21 ms | 1.27 ms | 3.36 ms | 388.0 KiB | 827 |
| 5 | 1.37 ms | 1.46 ms | 3.53 ms | 463.6 KiB | 730 |

### `auth.require`

**Why we benchmark it.** An app calls auth.require next to the data on every route that needs more than the default requirement. It reads the session from the store and recomputes its assurance from the evidence the session holds, with no cache.

**What poor performance would mean.** Every protected call pays it, so a slow check slows every sensitive route of the app for as long as the session lives.

**Expected growth: O(n).** A session keeps only the newest evidence per method and authenticator, so its evidence is at most one entry per authenticator plus the password; the assurance is one sorted pass over it.

**Measured on a shorter ladder (1, 2, 3, 4, 5).** The evidence is bounded by the account's authenticators, at most five, so the ladder is every count it can have.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| authenticators | swept | TOTP authenticators on the account, each verified once, so the session holds evidence from each. |
| step-ups | fixed at "one per authenticator" | Repeated verifications replace their own evidence instead of adding to it. |
| requirement | fixed at "default" | The default AAL2 requirement, which the session meets. |

**Deliberately not covered**

- **no session**: A request without a session stops at the cookie parse, which the session-cookies benchmark measures.

**In the end-to-end run:** Called by the app on its own protected routes.

**Measured: O(log n)** (exponent 0.15, 5 sizes): 🟡 close (neighbouring class).

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 1 | 70.3 µs | 98.5 µs | 147 µs | 27.9 KiB | 14,224 |
| 2 | 72.2 µs | 80.5 µs | 334 µs | 31.6 KiB | 13,841 |
| 3 | 77.3 µs | 85.9 µs | 337 µs | 35.3 KiB | 12,930 |
| 4 | 83.5 µs | 92.7 µs | 361 µs | 39.8 KiB | 11,983 |
| 5 | 90.6 µs | 97.1 µs | 404 µs | 44.4 KiB | 11,032 |

### `memoryStore().listByOwner`

**Why we benchmark it.** The session list and remote revoke read every session an account owns; an account signed in on many devices has many.

**What poor performance would mean.** Slower session pages and revocation for heavy users.

**Expected growth: O(n).** The owner's records are collected in one pass.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| records | swept | Records one owner holds in the collection. |

**Deliberately not covered**

- **a SQL store**: store/sql is not exported until CI runs it against real database servers; its cost is the database's.

**In the end-to-end run:** Runs on the session list, not on every request.

**Measured: O(n)** (exponent 0.99, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 35.4 µs | 36.8 µs | 136 µs | 26.4 KiB | 28,254 |
| 40 | 69.1 µs | 71.1 µs | 220 µs | 49.2 KiB | 14,464 |
| 80 | 136 µs | 146 µs | 440 µs | 98.1 KiB | 7,332 |
| 160 | 271 µs | 276 µs | 796 µs | 195.3 KiB | 3,697 |
| 320 | 539 µs | 552 µs | 1.60 ms | 385.8 KiB | 1,854 |
| 640 | 1.08 ms | 1.11 ms | 3.21 ms | 777.1 KiB | 923 |
| 1280 | 2.16 ms | 2.27 ms | 4.31 ms | 1.5 MiB | 464 |
| 2560 | 4.29 ms | 4.34 ms | 6.63 ms | 3.0 MiB | 233 |
| 5120 | 8.60 ms | 8.76 ms | 11.2 ms | 6.1 MiB | 116 |
| 10240 | 17.0 ms | 17.2 ms | 19.5 ms | 12.2 MiB | 59 |

### `memoryStore().consumeOnce`

**Why we benchmark it.** Every single-use secret (a TOTP time step, a step-up challenge, later a recovery code) is redeemed with consumeOnce, under the store's lock.

**What poor performance would mean.** Slower MFA and step-up for everyone once the store holds many records.

**Expected growth: O(1).** One keyed lookup and one write, whatever the number of other records.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| records | swept | Other records in the store. |

**Deliberately not covered**

- **a SQL store**: Not exported in phase 3; see listByOwner.

**In the end-to-end run:** Runs on MFA and step-up, not on every request.

**Measured: O(log n)** (exponent 0.24, 10 sizes): 🟡 close (neighbouring class).

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 12.1 µs | 20.1 µs | 20.0 µs | 5.1 KiB | 82,474 |
| 40 | 12.0 µs | 15.2 µs | 17.0 µs | 5.1 KiB | 83,333 |
| 80 | 11.9 µs | 19.0 µs | 19.0 µs | 5.1 KiB | 84,211 |
| 160 | 11.5 µs | 14.8 µs | 20.0 µs | 5.1 KiB | 86,957 |
| 320 | 12.9 µs | 25.4 µs | 22.0 µs | 5.1 KiB | 77,417 |
| 640 | 13.5 µs | 38.8 µs | 15.0 µs | 5.1 KiB | 74,074 |
| 1280 | 15.0 µs | 38.2 µs | 17.0 µs | 5.1 KiB | 66,485 |
| 2560 | 14.8 µs | 21.7 µs | 17.0 µs | 5.1 KiB | 67,417 |
| 5120 | 18.5 µs | 21.6 µs | 21.0 µs | 5.1 KiB | 54,177 |
| 10240 | 28.2 µs | 36.8 µs | 32.0 µs | 5.1 KiB | 35,450 |

### `memoryStore().increment`

**Why we benchmark it.** The throttles (phase 4) count every sign-in attempt per account, address and network with increment.

**What poor performance would mean.** Throttling that slows as counters accumulate would tax exactly the requests an attack sends.

**Expected growth: O(1).** One keyed counter read and write, whatever the number of other counters.

**Variables that could change its cost**

| Variable | How it is handled | What it is |
| --- | --- | --- |
| counters | swept | Other counters in the store. |

**Deliberately not covered**

- **a SQL store**: Not exported in phase 3; see listByOwner.

**In the end-to-end run:** Used by the phase 4 throttles.

**Measured: O(1)** (exponent -0.00, 10 sizes): ✅ matches.

| requests | Median | p95 | CPU (median) | Heap Δ | Ops/s |
| --- | --- | --- | --- | --- | --- |
| 20 | 0.845 µs | 0.979 µs | 0.902 µs | 2.1 KiB | 1,183,442 |
| 40 | 0.836 µs | 0.931 µs | 0.878 µs | 2.1 KiB | 1,196,860 |
| 80 | 0.731 µs | 0.919 µs | 0.756 µs | 1.9 KiB | 1,367,923 |
| 160 | 0.808 µs | 0.893 µs | 0.835 µs | 1.9 KiB | 1,237,852 |
| 320 | 0.717 µs | 0.834 µs | 0.759 µs | 1.9 KiB | 1,394,900 |
| 640 | 0.735 µs | 0.802 µs | 0.754 µs | 1.9 KiB | 1,360,683 |
| 1280 | 0.746 µs | 0.910 µs | 0.770 µs | 1.9 KiB | 1,339,645 |
| 2560 | 0.747 µs | 0.896 µs | 0.762 µs | 1.9 KiB | 1,338,804 |
| 5120 | 0.748 µs | 0.817 µs | 0.761 µs | 1.9 KiB | 1,336,606 |
| 10240 | 0.725 µs | 0.804 µs | 0.741 µs | 1.9 KiB | 1,379,698 |

## 3. What makes up one end-to-end operation

Each function's measured cost is multiplied by how many times one end-to-end operation calls it. A function measured on its own includes everything it calls. So where one attributed function calls another, the nested time is subtracted from the caller (its _exclusive_ time). Every moment of the operation then belongs to at most one row. Shares are measured against the whole operation with the package, a figure measured directly. They are not measured against the _added_ time, which is the small difference of two noisy medians. They are estimates (each function was measured separately); the remainder is shown as _unattributed_.

**At 640 requests** (whole operation: 21.4 ms)

| Function | Calls / operation | Time if called that often | Exclusive time | Share of operation |
| --- | --- | --- | --- | --- |
| `session-cookies` | 1 | 180 µs | 180 µs | 0.8% |
| `create-auth` | 0 | 0 | 0 | 0.0% |
| `define-auth-policy` | 0 | 0 | 0 | 0.0% |
| `express-public-paths` | 0 | 0 | 0 | 0.0% |
| `express-requests` | 0 | 0 | 0 | 0.0% |
| `fetch-with-auth` | 0 | 0 | 0 | 0.0% |
| `fetch-auth-routes` | 0 | 0 | 0 | 0.0% |
| `next-auth-handler` | 0 | 0 | 0 | 0.0% |
| `next-proxy` | 0 | 0 | 0 | 0.0% |
| `next-server-auth` | 0 | 0 | 0 | 0.0% |
| `tanstack-start-auth` | 0 | 0 | 0 | 0.0% |
| `tanstack-start-middleware` | 0 | 0 | 0 | 0.0% |
| `store-list-by-owner` | 0 | 0 | 0 | 0.0% |
| `store-consume-once` | 0 | 0 | 0 | 0.0% |
| `store-increment` | 0 | 0 | 0 | 0.0% |
| _unattributed_ |  |  | 21.2 ms | 99% |

**At 10240 requests** (whole operation: 336 ms)

| Function | Calls / operation | Time if called that often | Exclusive time | Share of operation |
| --- | --- | --- | --- | --- |
| `session-cookies` | 1 | 2.45 ms | 2.45 ms | 0.7% |
| `create-auth` | 0 | 0 | 0 | 0.0% |
| `define-auth-policy` | 0 | 0 | 0 | 0.0% |
| `express-public-paths` | 0 | 0 | 0 | 0.0% |
| `express-requests` | 0 | 0 | 0 | 0.0% |
| `fetch-with-auth` | 0 | 0 | 0 | 0.0% |
| `fetch-auth-routes` | 0 | 0 | 0 | 0.0% |
| `next-auth-handler` | 0 | 0 | 0 | 0.0% |
| `next-proxy` | 0 | 0 | 0 | 0.0% |
| `next-server-auth` | 0 | 0 | 0 | 0.0% |
| `tanstack-start-auth` | 0 | 0 | 0 | 0.0% |
| `tanstack-start-middleware` | 0 | 0 | 0 | 0.0% |
| `store-list-by-owner` | 0 | 0 | 0 | 0.0% |
| `store-consume-once` | 0 | 0 | 0 | 0.0% |
| `store-increment` | 0 | 0 | 0 | 0.0% |
| _unattributed_ |  |  | 333 ms | 99% |

## Cost model

Estimates use two bracketing price shapes. **Low** is CPU-priced compute ($0.040 per vCPU-hour, billed on CPU time). **High** is duration-and-memory-priced functions ($0.000017 per GB-second, billed on wall time, at least 128 MB reserved). Both are rounded list prices and change over time; override them in `benchmark.config.json` → `costRates` to match your platform and negotiated pricing.

## Environment and method

- Run: `2026-11-21T20:15:28.026Z` → `2026-11-21T20:17:24.836Z` (117 s), npm run benchmark
- Machine: Apple M3, 8 logical core(s) (8 physical), 24576 MB RAM, darwin/arm64, Node v24.20.0, local
- Git: `c97b56d5ba96a42c556868b78a6bee61a2250fd7` on `phase-3` (uncommitted changes)
- Sizes: 20, 40, 80, 160, 320, 640, 1280, 2560, 5120, 10240 requests: One HTTP request an app hands to test-cap. Each function names what its n counts instead (cookies on a request, key-ring entries, policy requirements, public paths, stored records, password characters), because the cost of an authentication request grows with those, not with a batch size. 640 is a busy minute of sign-in traffic for one of the owner's apps.

**Do not compare these numbers with another machine's, another day's, or another package's.** They show how _this_ package's cost changes between runs on comparable hardware, and how it scales with size. See [READING-BENCHMARKS.md](../READING-BENCHMARKS.md).

