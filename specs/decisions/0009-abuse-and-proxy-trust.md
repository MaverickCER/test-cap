# 0009: Abuse protection: throttling, proxy trust and uniform replies

## Status

Accepted (2026-11-15). Implemented in phase 4 (throttling, the failure ceiling, the credential-stuffing detector and
challenge hook, proxy trust and enumeration defences), with each new method in phase 5 joining the same counters.
Amended 2026-11-20: section 8 adds a request limit on every route, and makes every limit changeable or replaceable.
Amended 2026-11-21 by [ADR 0030](0030-use-existing-libraries-for-limits-and-client-addresses.md): the limits count with
rate-limiter-flexible, and client addresses are parsed with ipaddr.js and forwarded-parse.
Amended 2026-11-24: Open 4 is decided (section 8: production and staging refuse a request with no client address), and
section 5 reads `Forwarded` one element at a time from the right.
Amended 2026-11-24, after an independent review of phase 4. Section 2's two account keys are now kept per kind of
secret: a password, a TOTP code, a recovery code. A success clears only its own kind. With one shared budget, a correct
password cleared the failures of TOTP guesses, so whoever held the password guessed codes without waiting. Sign-in and a
password step-up still share the password's budget; TOTP verification and a code step-up share the code's. Section 4's
detector also counts a sign-in the throttle refuses. The client throttle allows about 15 checked failures in 15 minutes,
below the 20 that flag a client. The throttle's count restarts with each window, so with the Open 1 values the longest
wait is about 8.5 minutes, not 15. The throttle's and the detector's windows and delays are at most a year.

Answers [handoff question](../../GLOSSARY.md) 9 (abuse protection). The boundary with secure-cap for CSRF and XSS is ADR
0011's.

Tests:

- `test/abuse/throttle.test.ts` (the delay curve, the keys, what a success clears, a parallel burst getting one
  attempt, and no lost count);
- `test/abuse/counter-keys.test.ts` (failures count per account, per account and client, and per client, and an
  address no account holds is throttled exactly like one an account holds);
- `test/abuse/second-factor-throttle.test.ts` (TOTP verification and step-up go through the same throttle);
- `test/abuse/failure-ceiling.test.ts` (an authenticator stops accepting attempts after 100 consecutive failures; a
  success before the ceiling resets the count);
- `test/abuse/credential-stuffing-detector.test.ts` (failures across many accounts flag the client; with a hook the
  sign-in needs the app's challenge, without one the throttle runs with no free attempts);
- `test/abuse/client-address.test.ts` (the client is the socket's peer; the named forwarding header is read only when
  that peer is a trusted proxy; `Forwarded` is read one element at a time from the right, a malformed element the
  walk reaches is `unknown`; an IPv4 address and its IPv4-mapped IPv6 form are one client);
- `test/abuse/client-address-required.test.ts` (production and staging refuse a request with no client address with
  the fixed 500, and a Web-Request adapter with no source of addresses refuses to start; `requireClientAddress: false`
  serves it uncounted and is reported once; development and test serve it uncounted);
- `test/abuse/store-failure.test.ts` (a store failure while counting fails the attempt closed);
- `test/attacks/email-send-flooding.test.ts` (sends per address and per client stop at the limit, with an unchanged
  reply);
- `test/attacks/lockout-denial-of-service.test.ts` (failures never disable the account; the ceiling stops only the
  authenticator that failed, and recovery brings a password at the ceiling back);
- `test/attacks/ipv6-rotation-throttle-bypass.test.ts` (rotating addresses inside one /64 does not reset the throttle);
- `test/attacks/spoofed-forwarded-for.test.ts` (a client-supplied forwarding header changes nothing without a trusted
  proxy, a forged copy of the header the app did not name changes nothing behind one, and `Forwarded` elements a
  client prepends, well-formed or not, leave it counted under the address its proxy appended);
- `test/attacks/credential-stuffing.test.ts`, `password-brute-force.test.ts`, `totp-brute-force.test.ts`,
  `otp-attempt-limit-race.test.ts` and `throttle-counter-race.test.ts`;
- `test/attacks/double-slash-path-bypass.test.ts` (no path form reaches a sign-in route without its counters);
- `test/attacks/user-enumeration-responses.test.ts` (sign-in, sign-up and recovery replies are byte-identical for an
  existing and a missing account);
- `test/attacks/user-enumeration-timing.test.ts` (the reply time for a missing account, and for an account with no
  password, falls within the spread of an existing one, with the dummy argon2 in place);
- `test/abuse/request-limit.test.ts` (every route's default, each way to change it, a rate-limiter-flexible limiter in
  place of the default, the reply, and a request with no client address);
- `test/abuse/limit-options.test.ts` (`throttle: false` refused in production and staging, the app's own `Throttle`,
  and a failure ceiling that can be lowered but not raised);
- `test/security/rate-limit.test.ts` (how a limiter's answer becomes a decision, each route's rule, and the startup
  check);
- `test/attacks/sign-up-flooding.test.ts`, `request-flooding.test.ts` and `limiter-path-bypass.test.ts`;
- `test/topology/request-limit.test.ts` (the same counts and replies through every adapter);
- `test/failure/rate-limit.test.ts` (a failing counter ends the request with a 500 before its route runs).

The recommendations under Open are provisional defaults until the owner decides.

## Context

Question 9 asked for rate limiting, lockout or throttling, account enumeration (uniform replies and timing), credential
stuffing, and the split between what test-cap enforces and what is left to secure-cap.

Lockout turns brute-force protection into a denial of service: anyone who knows a username can lock its owner out.
NIST SP 800-63B-4 instead caps consecutive failures per authenticator at 100, and leaves the speed of guessing to
throttling. The plan follows it: throttle, never lock out.

Better Auth's advisories show how throttles fail in practice: by IPv6 rotation (`p6v2-xcpg-h6xw`), by a race in the
counter (`44jh-23m7-hpcf`, `2f9c-7xj7-gh55`), and by a path form that skips the limiter (`x732-6j76-qmhm`). A throttle
keyed on the client address also fails when the address itself can be forged through `X-Forwarded-For`.

Throttling guesses leaves one gap: routes where nothing fails. Sign-up writes an account, a pre-auth session and an
event on every call, and only the mail after it was limited, so one client could create records without bound.

## Decision

### 1. Throttle, never lock out

Failed attempts slow further attempts on the same key; they never disable an account. Passwords, TOTP codes and saved
recovery codes go through the throttle. An email confirmation code is bounded more tightly instead: 5 wrong attempts
over the code's life kill it, so a new one must be sent, and sends are limited by section 7 (Open 1).

Why: a throttle makes guessing slow for an attacker without giving them a way to lock out the owner.

### 2. Three counter keys, each an atomic `increment`

| Key                | Stops                                                                           |
| ------------------ | ------------------------------------------------------------------------------- |
| Account            | Many addresses guessing one account                                             |
| Account and client | One address guessing one account, without slowing the owner elsewhere as much   |
| Client (IP or /64) | One address guessing across many accounts, or one host rotating through its /64 |

The client is an IPv4 address, or an IPv6 address's /64, so the per-IP and per-/64 keys are one key. An IPv4-mapped
IPv6 address counts as its IPv4 address. The account key is the identifier as typed (normalised), not the account id,
so an address no account holds is throttled exactly like one an account holds. A signed-in session's TOTP check and
step-up use its account's address, so sign-in, recovery and step-up of one account share one budget.

On the two account keys every attempt counts with the store's atomic `increment` before the secret is checked, and an
attempt past the free ones must also win a compare-and-set on the key's block record, so a parallel burst gets one
attempt, not one each. The client key counts failures only, after the check, so people behind one shared address are
not slowed by each other's successes. A success clears the account's keys, never the client's.

Why: one key alone is always bypassable: per-IP alone by a botnet, per-account alone by one address spraying many
accounts, per-address IPv6 by rotation inside a /64 that one host typically holds. Counting before the check closes
the race in which parallel requests each read the old count.

### 3. At most 100 consecutive failures per authenticator

An authenticator that reaches 100 consecutive failures stops accepting attempts. The account and its other
authenticators are unaffected, and recovery (ADR 0007) remains open. A success before the ceiling resets the count.
A TOTP code is checked against each of the account's authenticators, and counts a failure on them only when none takes
it, so a person who always uses one device never wears out another. What re-enables an authenticator that has reached
it is open (see Open).

Why: this is the NIST ceiling, applied per authenticator as the glossary defines attempt limits. Applying it to one
authenticator, not the account, keeps "never lock out" true for the account.

### 4. A credential-stuffing detector escalates to an app challenge hook

test-cap watches for the pattern of credential stuffing: failures spread across many accounts rather than
concentrated on one. When it fires, it calls the app's challenge hook, which can require a challenge of the app's
choice before further attempts. There is no CAPTCHA by default.

Why: stuffing uses valid username and password pairs from other breaches, so per-account throttling sees one attempt
per account and never fires. A hook leaves the choice of challenge, and of any third-party service, to the app.

Override: the app supplies the challenge hook, a `ChallengeHook`. With one, a flagged client's sign-in is refused with
403 `challenge-required` until the hook passes it. Without one, every attempt from a flagged client is throttled with
no free attempts, and its failure event names `credential-stuffing`.

### 5. The client address comes from the socket, or from a proxy the app declared

`PlainRequest.clientAddress` is the socket's peer address (ADR 0003). A forwarding header is read only when the app
declared who stands in front of it, in one of two ways, and never ad hoc:

- **Its own proxies.** `trustedProxies` lists their IP addresses or CIDR ranges (`["10.0.0.5", "10.1.0.0/16"]`). From
  a peer in the list, the one header the app names is read: `X-Forwarded-For` by default, or `Forwarded` (RFC 7239),
  whose `for=` node is read with any quotes, IPv6 brackets and port removed. The client is the right-most hop that is
  not in the list, so a CDN in front of a load balancer is handled by listing both. A hop may carry a port
  (`192.0.2.1:443`, `[2001:db8::1]:443`); it is removed. Both headers are read the same way, one hop at a time from
  the right: `Forwarded` is split at each comma outside a quoted string, counting quotes from the right, and each
  element is parsed on its own, so what a client puts before its proxy's element is never reached. A `Forwarded`
  element the walk reaches that is not RFC 7239, or that has no `for=` node, is `unknown`, as the RFC spells a hidden
  node; an empty element names no hop.
- **A platform preset.** `trustedProxies: platform(name, options)` names the one header that platform sets, how to
  read it, and the peers it may come from. Vendor headers are read only through a preset.

| Preset       | Header read                               | Peers                                        | Vendor source (read 2026-11-17)                                                                                                                                        |
| ------------ | ----------------------------------------- | -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `aws-alb`    | `X-Forwarded-For`, right-most non-ALB hop | the app's ALB subnets, passed as `peers`     | <https://docs.aws.amazon.com/elasticloadbalancing/latest/application/x-forwarded-headers.html>                                                                         |
| `cloudfront` | `CloudFront-Viewer-Address`, port removed | `CLOUDFRONT_ORIGIN_FACING` ranges, passed    | <https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html>                                                                    |
| `cloudflare` | `CF-Connecting-IP`                        | Cloudflare's published ranges, passed        | <https://developers.cloudflare.com/fundamentals/reference/http-headers/>, <https://www.cloudflare.com/ips/>                                                            |
| `vercel`     | `x-real-ip`                               | the platform: every request comes through it | `@vercel/functions` `ipAddress()` source (3.11.3); <https://vercel.com/docs/headers/request-headers>                                                                   |
| `fly`        | `Fly-Client-IP`                           | the platform                                 | <https://docs.fly.io/networking/request-headers>                                                                                                                       |
| `netlify`    | `x-nf-client-connection-ip`               | the platform                                 | Netlify staff, <https://answers.netlify.com/t/upcoming-change-stripping-exposed-netlify-headers-from-function-and-proxy-requests/52665>; not in Netlify's product docs |
| `nginx`      | `X-Real-IP`, or `X-Forwarded-For` if told | the app's nginx addresses, passed            | <https://nginx.org/en/docs/http/ngx_http_realip_module.html>                                                                                                           |

The full notes, with quotes and what each vendor leaves unstated, are in the research note of 2026-11-17
(`research-proxy-platforms-2026-11-17.md` in the design folder). test-cap ships no address ranges, so none go stale in
it: a preset whose peers change takes them from the app, which can refresh them from the vendor's list. Every preset is
tested in simulation (`test/topology/`), through every adapter; **none has been verified on the real platform.**

When a request carries a forwarding header that test-cap did not read, the app's `onDiagnostic` hook is told once:
an undeclared proxy makes every client behind it share one address in the throttle.

Why: a forwarding header is a header anyone can send. Reading it from an untrusted peer would let an attacker choose
the IP key of every counter. Reading more than one header would let one through anyway: a proxy that sets
`Forwarded` passes a client's own `X-Forwarded-For` along untouched, and nginx passes a client's `X-Real-IP` along
unless its configuration sets that header itself.
Naming the vendor's header in a preset, with the vendor's source, keeps each such choice reviewable in one place.

Override: the app declares `trustedProxies` (addresses and ranges, with `forwardedHeader: "forwarded"` when its proxy
sets `Forwarded`) or a `platform` preset.

### 6. Replies and timing reveal nothing about accounts

Sign-in, sign-up and recovery give the same reply whether or not the account exists, and take the same time. Whenever
a password sign-in verifies no stored password hash (the account does not exist, has no password, or is disabled), it
still runs an argon2id hash with the same parameters against a dummy value, so the time spent hashing matches a real
check.

Why: a reply or a delay that differs for existing accounts turns sign-in into an account directory, which feeds
stuffing and targeted phishing. Running the dummy hash only for unknown accounts would still let timing tell a
passkey-only account from no account.

### 7. Email sends are throttled

Every flow that sends email (sign-up confirmation, address change, recovery and email sign-in) counts each send with
the atomic `increment`, keyed per destination address and per IP and IPv6 /64. Over the limit, no mail is sent and
the reply is the same as for a send, with the wait time the UX contract shows (ADR 0025).

Why: a sending route is a free way to flood someone's inbox with mail from the app's domain, and the failure counters
of section 2 never fire, because nothing fails.

Override: `emailLimit` changes the rules per address and per client, or puts rate-limiter-flexible limiters of the
app's in place of the store's counters (ADR 0030); `false` turns them off in development and test, and production and staging refuse it
(section 8).

### 8. Every request is limited per client, and every limit can be changed or replaced

The owner's rule for every limit: a sensible default, on, with every value changeable, a rule per route, and a way
to turn it off or put the app's own implementation in its place behind a small interface.

**The request limit.** Every request the dispatcher answers is counted before anything else runs: under the route it
names and the client key of section 2 (an IPv4 address, or an IPv6 /64). Counting is rate-limiter-flexible's over
the store's atomic `increment` by default (ADR 0030), so instances that share a store share the counts, and a
parallel burst gets the rule's count and no more. Over its rule, a request answers `429 rate-limited` with `Retry-After` in seconds, the reply the throttle gives.
It is on in every mode, development and test included.

A route's rule is keyed by its route id: its path after `/auth/`, such as `sign-in` or `totp/verify`. Three more ids
cover what runs no route: `pages` (every default page shown by `GET`), `assets` (the hashed page assets) and
`unmatched` (every 404 and 405).

| Route id                                                                                       | Default rule | Why                                                                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| every id without its own rule                                                                  | 100 per 10 s | Better Auth's default. A default page costs one page and two asset requests, so a person never meets it.                                                                                                                                                                    |
| `sign-in`, `step-up`, `totp/verify`, `totp/enrol`, `totp/confirm`, `email/confirm`, `recovery` | 10 per 10 s  | Each checks a secret or starts enrolling one. 10 sits above the throttle's 5 free failures, so a person who mistypes meets the throttle's short wait first. Better Auth's 3 per 10 s on sign-in and two-factor routes can stop a person retrying a TOTP code in 10 seconds. |
| `sign-up`                                                                                      | 20 per hour  | Each sign-up writes an account, a session and an event. 20 per client per hour is already the confirmation-mail limit (Open 1), so a 21st sign-up would get no mail.                                                                                                        |

`totp/confirm` is in the second row because it checks a TOTP code, as `totp/verify` does.

**How a request finds its rule.** The id is decided on the raw path the dispatcher routes on (ADR 0003 §2), never on
a normalised copy, so no spelling counts under one rule while running another route:

- An ambiguous path (a trailing slash, a doubled slash, a dot segment, percent-encoding under `/auth`) is refused
  with a 400 before anything is counted or run. Such a refusal costs no store call; counting it would cost one.
- A spelling no route has, another letter case included, is `unmatched`: one key per client, so new spellings mint no
  new counters.
- A path outside `/auth`, the gateway's `publicBasePath` prefix included, is not answered by test-cap at all.
- A query, a fragment or an absolute-form URL leaves the path, and so the route, the same.

`auth.session`, `auth.require` and `auth.admin` are calls from the app's own server, not requests, and are never
counted.

**A request with no client address** cannot be counted, as the throttle keeps no client key for one (section 2). The
owner decided Open 4 on 2026-11-24: production and staging need an address, set by `requireClientAddress` (`true` by
default). Adapters supply the address per request, and `createAuth` runs before any adapter exists, so the refusal
sits at the two points that can see the gap:

- **When an adapter starts.** A Web-Request adapter (`fetchAuth`, `withAuth`, `nextAuthHandler`,
  `tanstackStartAuth`) built with no `clientAddress` option refuses to start with a `ConfigError` naming the fix,
  unless a platform preset reads its header from every request (`vercel`, `fly`, `netlify`). The app's own
  `trustedProxies` do not lift it: their header is read only from a peer whose address is known. Express always has
  the socket's address.
- **When a request still arrives without one**, for instance when the `clientAddress` function answers `undefined` or
  a platform header is absent: the request ends with the fixed 500 before it is counted or run (fail closed, as a
  failing counter does), and the operator is told once with the code `client-address-missing`.

`requireClientAddress: false` serves such a request uncounted by the per-client limits, in any mode, for an app that
limits requests at its gateway; the operator is told once (`client-address-optional`). Development and test always
serve it uncounted and say so once (`client-address-missing`). The per-account counters apply in every case.

Why both points: a startup check alone misses a `clientAddress` function that answers nothing, and a request check
alone would let a deployment that can never see an address start and then answer every `/auth` request with a 500.

**The reply** is JSON, like every refusal. A form post from a default page gets that page again with the wait, when the
page opens without the store; the TOTP enrolment and step-up pages start a ceremony when they open, so a refused
post to them answers JSON. A refused state-changing route emits its failure event with the detail `request-limit`
and no account; a refused read emits nothing, as a refused read never does. The limit is counted before the body is
read, so the reply cannot depend on any account.

**When the counter fails**, the request ends with the fixed 500 before its route runs (fail closed; see
[dependency-failures.md](../dependency-failures.md)).

**Changing and replacing it.** `createAuth` takes one option, `rateLimit`:

| Setting                      | What it does                                                                                                                                                                                                                                                                    |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `windowMs`, `max`            | Change the default rule, the 100 per 10 seconds. The stricter rules keep their own values.                                                                                                                                                                                      |
| `rules: { [routeId]: rule }` | A route's own rule: `{ windowMs, max }`, `false` for no limit on that route, a rate-limiter-flexible limiter, or a function of the request that answers a rule or `false`. A key that is no route id refuses to start, naming the ids.                                          |
| `limiter`                    | A factory that builds each `{ windowMs, max }` rule's limiter over the app's own backend from rate-limiter-flexible's options, `{ points, duration, keyPrefix }`. Keys are `<route id>\|<client key>`. The default builds `createStoreLimiter` over the `AuthStore` (ADR 0030). |
| `rateLimit: <limiter>`       | One rate-limiter-flexible limiter for every route, in place of every default.                                                                                                                                                                                                   |
| `rateLimit: false`           | No request limit, in any mode, for an app that limits at its gateway. The operator is told once (`rate-limit-off`).                                                                                                                                                             |

Why route ids rather than paths: an id names what runs, so it cannot be spelled two ways, and a typo is caught when
the app starts.

**The guessing limits follow the same rule.** `throttle` takes changed values (`ThrottleConfig`, each one left out
keeping its default), the app's own `Throttle` (`attempt`, `failed`, `succeeded`), or `false`. Production and staging
refuse `false`, because NIST SP 800-63B-4 §3.2.2 requires throttling failed attempts; the refusal says so. In
development and test, `false` lets every guess through and tells the operator once (`throttle-off`). The failure
ceiling of section 3 stays on whatever the throttle is: `failureCeiling` lowers it, and a value above 100 refuses to
start, citing the same section.

**The other limits too.**

| Limit                         | Default                                                     | Change                                           | Replace                                     | Off                                  |
| ----------------------------- | ----------------------------------------------------------- | ------------------------------------------------ | ------------------------------------------- | ------------------------------------ |
| Confirmation mail (section 7) | 1 a minute and 5 an hour per address, 20 an hour per client | `emailLimit: { perAddress: [rules], perClient }` | a limiter per rule, or `emailLimit.limiter` | `false` in development and test only |
| Email-code attempts (Open 1)  | 5 over the code's life                                      | `emailCodeAttempts`, from 1 to 5                 | none                                        | never                                |
| Stuffing detector (section 4) | 20 accounts in 15 minutes                                   | `stuffing: { distinctAccounts, windowMs }`       | `stuffing: StuffingDetector`                | `false` in development and test only |

Production and staging refuse `emailLimit: false` because the send limits are what stop sign-up and resend from
flooding someone's inbox with mail from the app's domain, and `stuffing: false` because stuffing spread across many
accounts is otherwise slowed by nothing past the per-account throttle. `perClient: false` is allowed in any mode: each
inbox keeps its own limit. The email-code attempts can go down but not up or off: 5 guesses at a 6-digit code succeed
1 time in 200,000, and that bound is the code's whole defence. Each mail limit's limiter gets keys such as
`address:ada@example.com` and `client:203.0.113.7`.

**Refusal events.** A refusal by a limit emits its failure event once per key and window by default
(`refusalEvents: "first"`): per client and route for the request limit, per identifier and client for the throttle,
and per account for an email code past its attempts. The first refusal takes the key's one point in a store limiter
whose window is the refusal's wait (ADR 0030), so instances that share a store share it; a store that cannot count it
lets the event through, and the refusal stands either way. `refusalEvents: "every"` emits one per refusal. Why: an attacker's flood of refused
requests would otherwise become a flood in the app's logs, and the first event already says who was refused and why.

How this compares with Better Auth's limiter, as its documentation describes it:

| Better Auth                                                | test-cap                                                          |
| ---------------------------------------------------------- | ----------------------------------------------------------------- |
| Off in development                                         | On in every mode                                                  |
| Memory storage by default, so each instance counts its own | The app's store, so every instance shares one count               |
| Trusts `X-Forwarded-For` by default                        | Reads a forwarding header only from a declared proxy (section 5)  |
| A path form skipped it (`x732-6j76-qmhm`)                  | Keyed on the route the raw path names; an ambiguous path is a 400 |
| `customRules` per path                                     | `rules` per route id, checked at startup                          |

## Consequences

- An attacker can slow an account's owner by failing against it, but never lock the account. The owner's passkey and
  their other authenticators still work.
- **Stated cost: an attacker who knows an identifier can disable its password.** 100 failed guesses drive the password
  authenticator to the ceiling of section 3. For an account that holds only a password and TOTP, TOTP alone is AAL1,
  so the owner can no longer reach AAL2 and is left with a saved recovery code or email recovery (ADR 0007) until the
  password is re-enabled (Open 7). An account with a passkey keeps AAL2 through it.
- Every new method that checks a guessable secret joins the same counter keys, so the IPv6 and race tests cover it.
- Deployments behind a proxy must declare it; until they do, every request appears to come from the proxy and the IP
  counters throttle everyone together. The `onDiagnostic` hook says so the first time a forwarding header arrives
  unread.
- The dummy argon2 spends the same CPU on a missing account as on a real one, which an attacker can use to load the
  argon2 concurrency semaphore.

## Limits

- **test-cap limits its own routes only.** Request limits, bot detection and network-level defences for the app's
  other routes are the app's.
- **The request limit's window is fixed.** A client can make up to twice a rule's count across the end of one window
  and the start of the next. A rate-limiter-flexible limiter of the app's can count another way.
- **A request with no client address is not counted** by the request limit or the throttle's client key in
  development and test, or anywhere with `requireClientAddress: false` (section 8). The startup refusal covers only
  the Web-Request adapters, which take the address as an option.
- **Throttling slows, it does not stop.** A distributed attack across many /64s and accounts stays under each key's
  threshold; the stuffing detector and the challenge hook are the answer to that, and their strength is the app's
  challenge.
- **Timing uniformity is statistical.** Tests check that the timing of a missing account falls within the spread of an
  existing one; they cannot rule out every side channel (the store's own lookup time, email delivery).
- **Only the one forwarding header the app or its preset names is read.** No other header is consulted.
- **A `Forwarded` element whose quoted value holds an escaped quote can be split wrongly.** The split counts quotes
  from the right and does not read escapes. Such a quote can join two elements, which forwarded-parse then splits
  correctly; beside a comma inside the same quoted value it can split one element, and each part then reads as
  `unknown`. A `for=` node never needs either, so only a proxy that writes such a value in another parameter meets
  it.
- **The stuffing detector counts approximately.** Each client and account pair counts as a new distinct account once
  per window, and that window starts at the pair's first failure, not at the start of the client's count. An account
  that failed late in one window and fails again early in the next is not counted again until its own window ends,
  so the flag can come later than exact counting would raise it. Stuffing tries each account about once, so it is
  counted as it happens.
- **The presets are simulated, not verified on the platforms.** Each follows the vendor's documentation as read on
  2026-11-17; a vendor that changes its headers changes what the preset should read.
- **A platform's ranges do not prove the request came through the app's own account.** Cloudflare's ranges are
  "shared by all proxied hostnames", so another Cloudflare customer's Worker can reach the app from them and set
  `CF-Connecting-IP` freely; Cloudflare's own answer is Authenticated Origin Pulls or a Cloudflare Tunnel, which test-cap
  cannot check. The same holds for CloudFront's ranges. Presets for platforms every request comes through (`vercel`,
  `fly`, `netlify`) assume the app has no other way in: an app reachable over Fly's private network, for one, can be
  sent a forged `Fly-Client-IP` by another app of the organisation.
- **`nginx` needs nginx to set the header.** With `proxy_set_header X-Real-IP $remote_addr` (or
  `$proxy_add_x_forwarded_for` for `X-Forwarded-For`), nginx overwrites or appends to what the client sent; without it,
  a client's own header reaches the app unchanged and the preset would read it.
- **`netlify` rests on an undocumented header.** Netlify documents `context.ip` for its functions, not the header; the
  preset reads `x-nf-client-connection-ip` on the strength of a Netlify staff answer.
- **The thresholds are defaults.** The values of Open 1 and Open 3 are the defaults, and each is configuration
  (`throttle`, `stuffing`). A tenant-wide jump in the failure ratio is not detected; see Open 3.
- **The failure ceiling can be triggered by anyone who knows an identifier.** It stops one authenticator, never the
  account, but for a password plus TOTP account that is enough to force recovery; see Consequences. Neither the
  account+IP key nor the throttle prevents it, because the ceiling counts every failure of the authenticator.

## Open

1. **Throttle values.** Recommendation: no delay for the first 5 failures on a key in 15 minutes, then a delay that
   doubles per failure up to 15 minutes, shown to the person as a wait time (the UX contract's rate-limit message).
   For email sends: at most 1 per destination address per minute and 5 per hour, and 20 per IP or /64 per hour.
   Email confirmation codes (built in phase 3) take no 15-minute window: 5 wrong attempts per code over the code's
   whole 24-hour life. The fifth kills the code, and the count alone refuses a sixth, so a
   store that fails the kill write buys no fresh guesses (finding F-2 in
   [dependency-failures.md](../dependency-failures.md#findings)). A new code starts a new count once the codes before
   it are revoked; a further try on a dead code answers `429` with the wait to the end of its life.
   _Built in phase 4 as the defaults, `DEFAULT_THROTTLE`; the send limits as `emailLimit` and the code's attempts as
   `emailCodeAttempts` (section 8)._
2. **What the account counter counts.** Recommendation: only failures of guessable secrets; a passkey ceremony is
   never delayed by password failures, so the owner keeps a way in during an attack on their password.
3. **The detector's trigger.** Recommendation: a failure rate across distinct accounts from one IP or /64, or a
   tenant-wide jump in the failure ratio, each with a configurable threshold, reported as a security event when it
   fires. _Built in phase 4: distinct accounts per client, 20 in 15 minutes by default (`stuffing`). The tenant-wide
   ratio is not built._
4. **Requests without a socket address.** Some runtimes behind the `fetch` adapter may not supply one. Recommendation:
   in production deployment mode, `createAuth` refuses to start when the adapter cannot supply `clientAddress` and no
   `trustedProxies` are declared; the per-account counters still apply everywhere. _Decided 2026-11-24 and built:
   production and staging refuse at the adapter's start and at the request, with `requireClientAddress: false` to opt
   out (section 8)._
5. **Other forwarding headers.** Recommendation: support `Forwarded` (RFC 7239) later through the same
   `trustedProxies` rule; never read vendor headers implicitly. _Built in phase 4: `forwardedHeader`, CIDR ranges and
   the `platform` presets of section 5. A Lambda or API Gateway event adapter is a follow-up._
6. **Email sending and timing.** Sign-up and recovery call `sendEmail` in one branch and not the other, so the
   reply time can reveal which branch ran. Recommendation: the reply is sent without waiting on `sendEmail` in both
   branches, through a queue the app supplies, so the reply time does not depend on email delivery.
7. **Re-enabling an authenticator at the ceiling.** Recommendation: a successful sign-in that meets the default
   requirement with the account's other authenticators, or a completed recovery, resets the count; each reset is a
   security event. _Built so far: a password replaced during recovery is a new authenticator with no failures. The
   reset by other authenticators is not built._
8. **"Passkey first when one exists" in the UX contract.** Telling the person a passkey exists after they type an
   identifier would reveal the account. Recommendation: passkey first comes from the browser (conditional mediation
   offers a passkey only when the device holds one); the server's reply to an identifier is the same for every
   identifier, real or not.
