# 0009: Abuse protection: throttling, proxy trust and uniform replies

## Status

Accepted (2026-11-15). Implemented in phase 4 (throttling, the failure ceiling, the credential-stuffing detector and
challenge hook, proxy trust and enumeration defences), with each new method in phase 5 joining the same counters.

Answers [handoff question](../../GLOSSARY.md) 9 (abuse protection). The boundary with secure-cap for CSRF and XSS is ADR
0011's.

Planned tests:

- `test/abuse/counter-keys.test.ts` (failures count per account, per account and IP, per IP, and per IPv6 /64);
- `test/abuse/throttle-not-lockout.test.ts` (failures slow further attempts; none locks the account);
- `test/abuse/failure-ceiling.test.ts` (an authenticator stops accepting attempts after 100 consecutive failures; a
  success before the ceiling resets the count);
- `test/abuse/counters-atomic.test.ts` (parallel failures lose no count);
- `test/abuse/credential-stuffing-detector.test.ts` (the detector escalates to the app's challenge hook; with no hook,
  throttling tightens and an event is emitted);
- `test/abuse/client-address.test.ts` (the client address comes from the socket; `X-Forwarded-For` is read only when
  the immediate peer is in `trustedProxies`);
- `test/abuse/ipv4-mapped-ipv6.test.ts` (an IPv4 address and its IPv4-mapped IPv6 form share one counter);
- `test/attacks/email-send-flooding.test.ts` (sends per address and per IP stop at the limit, with an unchanged
  reply);
- `test/attacks/lockout-denial-of-service.test.ts` (failures never disable the account; the ceiling stops only the
  authenticator that failed);
- `test/attacks/ipv6-rotation-throttle-bypass.test.ts` (rotating addresses inside one /64 does not reset the throttle);
- `test/attacks/spoofed-forwarded-for.test.ts` (a client-supplied `X-Forwarded-For` changes nothing without a trusted
  proxy);
- `test/attacks/double-slash-path-bypass.test.ts` (no path form reaches a sign-in route without its counters);
- `test/attacks/user-enumeration-responses.test.ts` (sign-in, sign-up and recovery replies are byte-identical for an
  existing and a missing account);
- `test/attacks/user-enumeration-timing.test.ts` (the reply time for a missing account, and for an account with no
  password, falls within the spread of an existing one, with the dummy argon2 in place).

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

## Decision

### 1. Throttle, never lock out

Failed attempts slow further attempts on the same key; they never disable an account. Every guessable secret test-cap
checks (passwords, TOTP codes, email codes, recovery codes) goes through the throttle.

Why: a throttle makes guessing slow for an attacker without giving them a way to lock out the owner.

### 2. Four counter keys, each an atomic `increment`

| Key            | Stops                                                                         |
| -------------- | ----------------------------------------------------------------------------- |
| Account        | Many addresses guessing one account                                           |
| Account and IP | One address guessing one account, without slowing the owner elsewhere as much |
| IP             | One address guessing across many accounts                                     |
| IPv6 /64       | One host rotating through the addresses of its own /64                        |

Each counter is an atomic `increment` in a time window (ADR 0002). An IPv4-mapped IPv6 address counts as its IPv4
address.

Why: one key alone is always bypassable: per-IP alone by a botnet, per-account alone by one address spraying many
accounts, per-address IPv6 by rotation inside a /64 that one host typically holds. Atomic counters close the race in
which parallel requests each read the old count.

### 3. At most 100 consecutive failures per authenticator

An authenticator that reaches 100 consecutive failures stops accepting attempts. The account and its other
authenticators are unaffected, and recovery (ADR 0007) remains open. A success before the ceiling resets the count.
What re-enables an authenticator that has reached it is open (see Open).

Why: this is the NIST ceiling, applied per authenticator as the glossary defines attempt limits. Applying it to one
authenticator, not the account, keeps "never lock out" true for the account.

### 4. A credential-stuffing detector escalates to an app challenge hook

test-cap watches for the pattern of credential stuffing: failures spread across many accounts rather than
concentrated on one. When it fires, it calls the app's challenge hook, which can require a challenge of the app's
choice before further attempts. There is no CAPTCHA by default.

Why: stuffing uses valid username and password pairs from other breaches, so per-account throttling sees one attempt
per account and never fires. A hook leaves the choice of challenge, and of any third-party service, to the app.

Override: the app supplies the challenge hook, a `ChallengeHook`. Without one, the detector tightens throttling and
emits a security event.

### 5. The client address comes from the socket

`PlainRequest.clientAddress` is the socket's peer address (ADR 0003). `X-Forwarded-For` is read only when that peer
is in the app's declared `trustedProxies` list, and then the client is the right-most address in the header that is
not itself a trusted proxy.

Why: `X-Forwarded-For` is a header anyone can send. Reading it from an untrusted peer would let an attacker choose the
IP key of every counter.

Override: the app declares `trustedProxies` (a `TrustedProxies` list) for its load balancer or CDN.

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

Override: the throttle values, with the others, are configuration (a `ThrottleConfig`; values in Open 1).

## Consequences

- An attacker can slow an account's owner by failing against it, but never lock the account. The owner's passkey and
  their other authenticators still work.
- **Stated cost: an attacker who knows an identifier can disable its password.** 100 failed guesses drive the password
  authenticator to the ceiling of section 3. For an account that holds only a password and TOTP, TOTP alone is AAL1,
  so the owner can no longer reach AAL2 and is left with a saved recovery code or email recovery (ADR 0007) until the
  password is re-enabled (Open 7). An account with a passkey keeps AAL2 through it.
- Every new method that checks a guessable secret joins the same four counters, so the IPv6 and race tests cover it.
- Deployments behind a proxy must declare it; until they do, every request appears to come from the proxy and the IP
  counters throttle everyone together.
- The dummy argon2 spends the same CPU on a missing account as on a real one, which an attacker can use to load the
  argon2 concurrency semaphore.

## Limits

- **test-cap throttles its own routes only.** General request rate limiting, bot detection and network-level defences
  for the app's other routes are outside test-cap.
- **Throttling slows, it does not stop.** A distributed attack across many /64s and accounts stays under each key's
  threshold; the stuffing detector and the challenge hook are the answer to that, and their strength is the app's
  challenge.
- **Timing uniformity is statistical.** Tests check that the timing of a missing account falls within the spread of an
  existing one; they cannot rule out every side channel (the store's own lookup time, email delivery).
- **Only `X-Forwarded-For` is read.** `Forwarded`, `X-Real-IP` and vendor headers are ignored in the first build; see
  Open.
- **The plan sets no thresholds.** Windows, delays and the detector's trigger are open.
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
2. **What the account counter counts.** Recommendation: only failures of guessable secrets; a passkey ceremony is
   never delayed by password failures, so the owner keeps a way in during an attack on their password.
3. **The detector's trigger.** Recommendation: a failure rate across distinct accounts from one IP or /64, or a
   tenant-wide jump in the failure ratio, each with a configurable threshold, reported as a security event when it
   fires.
4. **Requests without a socket address.** Some runtimes behind the `fetch` adapter may not supply one. Recommendation:
   in production deployment mode, `createAuth` refuses to start when the adapter cannot supply `clientAddress` and no
   `trustedProxies` are declared; the per-account counters still apply everywhere.
5. **Other forwarding headers.** Recommendation: support `Forwarded` (RFC 7239) later through the same
   `trustedProxies` rule; never read vendor headers implicitly.
6. **Email sending and timing.** Sign-up and recovery call `sendEmail` in one branch and not the other, so the
   reply time can reveal which branch ran. Recommendation: the reply is sent without waiting on `sendEmail` in both
   branches, through a queue the app supplies, so the reply time does not depend on email delivery.
7. **Re-enabling an authenticator at the ceiling.** Recommendation: a successful sign-in that meets the default
   requirement with the account's other authenticators, or a completed recovery, resets the count; each reset is a
   security event.
8. **"Passkey first when one exists" in the UX contract.** Telling the person a passkey exists after they type an
   identifier would reveal the account. Recommendation: passkey first comes from the browser (conditional mediation
   offers a passkey only when the device holds one); the server's reply to an identifier is the same for every
   identifier, real or not.
