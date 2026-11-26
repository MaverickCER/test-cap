# Threat model

What each test-cap flow must withstand, and which design element stops each threat. Flows F01–F22 are described in
[architecture.md](architecture.md); each design element is owned by the ADR named beside it, under
[decisions/](decisions/); each threat's negative test is an entry in [attack-catalogue.md](attack-catalogue.md).
Terms follow the [glossary](../GLOSSARY.md).

This is an internal design document. It records what test-cap is designed and tested against, for internal readers.
It is not a pen test and makes no compliance claim.

## How to read a flow

Each flow section lists:

- **Assets**: what an attacker wants from the flow.
- **Boundaries**: the trust boundaries the flow crosses, from the table below.
- **Threats**: one row per threat, tagged with a STRIDE category (**S**poofing, **T**ampering, **R**epudiation,
  **I**nformation disclosure, **D**enial of service, **E**levation of privilege). "Stopped by" names the design element
  and its ADR. "Entry" names the attack-catalogue ids whose tests prove it; a docs test checks that every id exists.
- **Residual risks**: what remains after the design, stated plainly.

`O1`–`O16` point to [Open](#open) items: questions the plan leaves unsettled. Each recommendation there is a
provisional default until the owner decides. Where a threat rests on one, the row describes the recommendation, and
its test pins that recommendation until then.

## Attacker model

| Attacker                              | Can                                                                                                                                                         | test-cap's aim                                                                                                                                                                                                                                      |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Network attacker                      | Observe and change traffic where TLS is absent; replay captured requests.                                                                                   | Production refuses a non-HTTPS origin; cookies are `__Host-` and Secure; every secret that travels is single-use (ADR 0026, 0006, 0002).                                                                                                            |
| Malicious site in the same browser    | Send cross-site requests and top-level navigations, frame pages, mail the user links, and, from a sibling subdomain it controls, set cookies on the parent. | CSRF checks, SameSite=Lax, `__Host-` cookies, `frame-ancestors 'none'`, same-origin `returnTo` (ADR 0011, 0006, 0026).                                                                                                                              |
| Credential-stuffing botnet            | Try breached pairs from many IPv4 and IPv6 addresses at low per-address rates.                                                                              | Throttles per account, account+IP, IP and /64; a detector that escalates to the app's challenge hook; breached-password screening; AAL2 by default, so a password alone opens nothing (ADR 0009, 0010, 0005).                                       |
| Malicious or compromised IdP          | Sign any assertion it likes, or impersonate another issuer; an issuer outside the trust config may be run by anyone.                                        | Only allowlisted issuers count; identities are keyed by issuer and subject; upstream `acr` counts only through a mapping; no email-based linking (ADR 0008, 0005; O1).                                                                              |
| Compromised tenant admin              | Use every admin call their role allows inside their tenant.                                                                                                 | No reach into other tenants; impersonation and break-glass need a fresh AAL2+ session, a reason and a time limit, are flagged on every event, and block credential changes (ADR 0012, 0014).                                                        |
| Attacker with database read           | Copy every table.                                                                                                                                           | Nothing read is usable as-is: sessions, API keys, delegations, codes and recovery codes are hashed; TOTP seeds are encrypted under a key outside the database; passwords are argon2id; passkeys are public keys (ADR 0006, 0013, 0007, 0027, 0010). |
| Attacker with database write and keys | Change any row and hold every `AUTH_*` key.                                                                                                                 | None for authentication: such an attacker can enrol their own authenticator on any account. The audit trail detects rewriting back to the last checkpoint exported outside the database (ADR 0020).                                                 |

Database write alone, without the keys, is as strong as database write with them for authentication; the difference
is only that the audit chain then also breaks visibly.

**What test-cap does not defend against:**

- A compromised user device or browser: malware, a malicious extension, or a session cookie copied off the device.
  Sessions are not bound to a device key.
- A real-time phishing relay against passwords and TOTP. Only passkeys resist it; a requirement can demand phishing
  resistance (ADR 0005).
- A compromised mailbox. Email recovery gives its holder the recovery-only state; see F09 and O6.
- XSS, CSRF or injection in the app's own routes. That is the app's and secure-cap's (ADR 0011).
- A careless or malicious app developer: marking routes public, injecting a weak random source, relaxing defaults.
  The policy report lists every deviation; it cannot refuse them.
- A compromised dependency. Socket, Scorecard and pinned versions reduce the risk; they do not remove it.
- Volumetric denial of service, side channels on the host, and social engineering of administrators.

## Trust boundaries

| Id  | Boundary                                                                             |
| --- | ------------------------------------------------------------------------------------ |
| B1  | Browser and server: the network, under TLS.                                          |
| B2  | Other sites and the auth origin, inside one browser.                                 |
| B3  | Adapter and core: framework objects become bytes (ADR 0003, 0024).                   |
| B4  | Core and store: the `AuthStore` port and its atomic operations (ADR 0002).           |
| B5  | Core and email: `sendEmail` and the user's mailbox.                                  |
| B6  | Core and identity provider: OIDC and SAML round trips.                               |
| B7  | Core and app callbacks: `onEvent`, the challenge hook, `redact`, `exportCheckpoint`. |
| B8  | Core and HIBP: the breached-password range API.                                      |
| B9  | Administrator and core: the admin calls.                                             |
| B10 | Agents and services and core: delegations and API keys.                              |

## F01: Sign-up

Identifier first; the account sits in the pre-auth state until it enrols a passkey, or a password plus TOTP, and
confirms its address (F08).

**Assets:** the identifier's ownership, the new account, the pre-auth session. **Boundaries:** B1, B2, B3, B4, B5, B8.

| STRIDE | Threat                                                                                                         | Stopped by                                                                                                       | Entry                                                              |
| ------ | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| S      | An attacker registers the victim's address first and keeps a working authenticator after the victim proves it. | An unconfirmed sign-up never leaves the pre-auth state and holds no claim on the identifier (ADR 0021, 0008; O7) | `pre-account-hijack`                                               |
| S      | Two spellings of one address create two accounts, or reach another's account.                                  | One normalisation in the core; byte comparison in stores (ADR 0021, 0002)                                        | `identifier-normalisation-collision`                               |
| S      | An identifier saved before proof is trusted to find the account.                                               | Only confirmed identifiers resolve (ADR 0021)                                                                    | `unverified-identifier-trusted`                                    |
| T      | Concurrent sign-ups claim one identifier.                                                                      | `createUnique` (ADR 0002)                                                                                        | `concurrent-enrolment-collision`                                   |
| T      | The request sets server-owned fields such as verified flags or tenant.                                         | Only declared fields are parsed (ADR 0003)                                                                       | `mass-assignment-server-owned-fields`                              |
| T      | A pooled insert hands the new user another request's row.                                                      | Ids from the random source; single statements (ADR 0002; O4)                                                     | `store-insert-returns-foreign-row`                                 |
| E      | The pre-auth session token, known before enrolment, stays valid afterwards.                                    | The token rotates when enrolment completes (ADR 0006)                                                            | `session-fixation`                                                 |
| I      | Sign-up replies or timing reveal that an address is registered.                                                | Uniform replies and timing (ADR 0009)                                                                            | `user-enumeration-responses`, `user-enumeration-timing`            |
| E      | A breached password is accepted, or an HIBP outage counts as screened.                                         | Blocklist always on; outage recorded `indeterminate` (ADR 0010)                                                  | `breached-password-accepted`, `breach-check-outage-counts-as-pass` |
| D      | Sign-up is used to flood a victim's inbox with confirmation mail.                                              | Per-address and per-IP send throttles (ADR 0009)                                                                 | `email-send-flooding`                                              |
| D      | One client signs up in a loop, filling the store with accounts nobody confirms.                                | Sign-up's request limit per IP or /64, counted before the account is created (ADR 0009)                          | `sign-up-flooding`                                                 |

**Residual risks.** Bots can create pre-auth accounts at the sign-up limit, 20 an hour per IP or /64; there is no CAPTCHA unless the app's
challenge hook adds one. HIBP lookups disclose a 5-character hash prefix to a third party. When HIBP is unreachable,
screening falls back to the bundled list, which is smaller.

## F02: Password sign-in

argon2id verify at a fixed cost under a concurrency limit, with a dummy hash whenever no stored password hash is
verified. Evidence: one factor, AAL1.

**Assets:** the password, the account, a session. **Boundaries:** B1, B2, B3, B4, B7.

| STRIDE | Threat                                                                                   | Stopped by                                                                                         | Entry                                                                             |
| ------ | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| S      | Credential stuffing across many accounts.                                                | Throttles per account, account+IP, IP and /64; detector escalates to the challenge hook (ADR 0009) | `credential-stuffing`                                                             |
| S      | Brute force against one account.                                                         | Per-account throttle; at most 100 consecutive failures per authenticator (ADR 0009)                | `password-brute-force`                                                            |
| S      | The throttle is dodged by races, IPv6 rotation or a forged forwarded header.             | Atomic `increment`; /64 keys; socket address unless from `trustedProxies` (ADR 0002, 0009)         | `throttle-counter-race`, `ipv6-rotation-throttle-bypass`, `spoofed-forwarded-for` |
| S      | A truncated or case-folded password verifies.                                            | Normalised once to NFC, then hashed whole; over-long input rejected (ADR 0010)                     | `password-altered-before-hashing`                                                 |
| E      | A password alone reaches a route, or another path mints access before the second factor. | Password is AAL1; the session is `step-up` pending until TOTP or a passkey (ADR 0005)              | `assurance-downgrade`, `alternate-path-skips-second-factor`                       |
| E      | A planted session token survives sign-in.                                                | Rotation on sign-in; unknown tokens never adopted (ADR 0006)                                       | `session-fixation`                                                                |
| S      | The victim is signed in to the attacker's account.                                       | CSRF token and Origin check on the sign-in form (ADR 0011)                                         | `login-csrf`                                                                      |
| I      | Replies or timing reveal whether the account exists.                                     | Uniform replies; dummy argon2id (ADR 0009)                                                         | `user-enumeration-responses`, `user-enumeration-timing`                           |
| D      | The attacker locks the owner out, or exhausts CPU with parallel long passwords.          | Throttle, never lock out; fixed cost, semaphore, 256-character limit (ADR 0009, 0010, 0018)        | `lockout-denial-of-service`, `argon2-cost-exhaustion`                             |
| T      | `returnTo` sends the user off-site after sign-in.                                        | Same-origin relative paths only (ADR 0026)                                                         | `open-redirect-protocol-relative`, `open-redirect-origin-prefix`                  |
| R      | Failures leave no trace, or the trace holds the password.                                | Every outcome emits OCSF 3002 with no secret field (ADR 0015)                                      | `auth-attempt-not-evented`, `secret-in-security-event`                            |
| D      | One client floods sign-in, in parallel bursts or from address after address of its /64.  | Request limit per IP or /64, counted atomically before the route runs (ADR 0009)                   | `request-flooding`                                                                |

**Residual risks.** A password phished or reused elsewhere still yields AAL1 evidence; the second factor is what
stops it. A slow, widely distributed botnet that stays under every per-key limit is slowed, not stopped. Throttling
can delay the real owner during an attack on their account.

## F03: TOTP enrolment

The secret comes from the injected random source, is shown once, is stored AES-GCM encrypted under
`AUTH_ENCRYPTION_KEY` with a key id, and counts only after one valid code confirms it.

**Assets:** the TOTP seed. **Boundaries:** B1, B3, B4.

| STRIDE | Threat                                                                     | Stopped by                                                                   | Entry                                |
| ------ | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------ |
| I      | A database read yields usable seeds.                                       | AES-GCM under a key held outside the database (ADR 0027)                     | `totp-secret-read-at-rest`           |
| I      | A seed is short or predictable.                                            | Random source default `crypto.getRandomValues`; fixed seed length (ADR 0003) | `weak-secret-generation`             |
| E      | An unconfirmed secret counts as an authenticator, or is shown again later. | Evidence only after a confirming code; never redisplayed (ADR 0027, 0005)    | `totp-unconfirmed-enrolment-counts`  |
| D      | Endless enrolments grow the list every verification reads.                 | At most 5 confirmed per account; one unconfirmed at a time (ADR 0027)        | `totp-authenticator-flood`           |
| T      | After key rotation, a ciphertext under a retired or wrong key id is used.  | Key id stored with each ciphertext; retired ids refused (ADR 0027, 0022)     | `totp-key-rotation-confusion`        |
| E      | A hijacked session enrols the attacker's TOTP without re-authenticating.   | Recent step-up for credential changes (ADR 0005; O2)                         | `sensitive-change-without-reauth`    |
| T      | A user removes another user's TOTP secret.                                 | Store calls scoped to tenant and subject (ADR 0002, 0012)                    | `idor-authenticator-removal`         |
| E      | Sessions opened before an authenticator change stay valid.                 | The change revokes the other sessions (ADR 0006, 0007)                       | `sessions-survive-credential-change` |

**Residual risks.** The seed is visible on screen once and lives in the user's authenticator app; test-cap cannot
protect either. Anyone holding the database and `AUTH_ENCRYPTION_KEY` holds every seed.

## F04: TOTP verification

RFC 6238 on Web Crypto HMAC against the injected clock; a time step already used is rejected. With a password, the
session reaches AAL2.

**Assets:** the second factor, the AAL2 session. **Boundaries:** B1, B3, B4.

| STRIDE | Threat                                                        | Stopped by                                                                             | Entry                                                           |
| ------ | ------------------------------------------------------------- | -------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| S      | A code is replayed within its time step.                      | Last accepted step stored; equal or earlier rejected (ADR 0027)                        | `totp-code-replay`                                              |
| S      | The client supplies the time the code is checked against.     | Server clock only (ADR 0027, 0003)                                                     | `totp-client-supplied-time`                                     |
| S      | Parallel guesses count as one attempt.                        | Atomic `increment` before checking (ADR 0002, 0009)                                    | `otp-attempt-limit-race`                                        |
| S      | The 6-digit code is guessed within its window.                | Throttles; at most 100 consecutive failures (ADR 0009, 0027)                           | `totp-brute-force`                                              |
| E      | A session cache treats the user as signed in before TOTP.     | No cache skips the assurance check (ADR 0006, 0005)                                    | `session-cache-skips-mfa`, `alternate-path-skips-second-factor` |
| I      | Code comparison leaks matching digits through timing.         | Constant-time comparison (ADR 0006, 0011)                                              | `secret-comparison-timing`                                      |
| D      | Repeated verifies grow the session, slowing every read of it. | Newest evidence per authenticator kept (ADR 0005); at most 5 authenticators (ADR 0027) | `totp-authenticator-flood`                                      |
| T      | A seed under a retired key id verifies after rotation.        | Key id checked on decrypt (ADR 0027, 0022)                                             | `totp-key-rotation-confusion`                                   |
| D      | Failures lock the owner out.                                  | Throttle, never lock out (ADR 0009)                                                    | `lockout-denial-of-service`                                     |
| R      | Failed second-factor attempts leave no trace.                 | OCSF 3002 on every outcome (ADR 0015)                                                  | `auth-attempt-not-evented`                                      |

**Residual risks.** TOTP is not phishing-resistant: a relay that forwards the code within its step succeeds. A
6-digit code has a one-in-a-million guess rate per attempt; the 100-failure limit bounds it, it does not remove it.

## F05: Passkey and security-key registration

`@simplewebauthn/server` with a challenge test-cap supplies, UV required. Attestation is verified when roots are
configured and never establishes AAL3 alone.

**Assets:** the credential binding, the key-protection record. **Boundaries:** B1, B2, B3, B4.

| STRIDE | Threat                                                                                         | Stopped by                                                                         | Entry                                                                      |
| ------ | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| S      | A response without user verification is accepted as two factors.                               | UV flag checked; without it the evidence is single-factor (ADR 0005, 0016)         | `passkey-uv-flag-not-checked`                                              |
| S      | The expected origin or RP ID comes from the request.                                           | `APP_ORIGIN` only (ADR 0026, 0016)                                                 | `passkey-origin-from-request`                                              |
| S      | A registration response is replayed against a reused challenge.                                | Challenges consumed once (ADR 0002, 0016)                                          | `webauthn-challenge-replay`                                                |
| T      | A credential id already bound to one account is registered to another, or two enrolments race. | `createUnique` on credential id per tenant (ADR 0002)                              | `passkey-credential-id-reuse`, `concurrent-enrolment-collision`            |
| E      | A synced passkey, or attestation alone, is recorded as AAL3-capable.                           | All four AAL3 conditions required (ADR 0005)                                       | `passkey-aal3-without-all-conditions`                                      |
| E      | An unanchored attestation chain or a poisoned revocation cache passes.                         | Library pinned past the 2026-09-13 fixes; roots configured locally (ADR 0016; O16) | `attestation-chain-not-anchored`, `attestation-revocation-cache-poisoning` |
| I      | Certificate URLs make the server fetch internal addresses.                                     | No network requests during registration (ADR 0016; O16)                            | `attestation-certificate-ssrf`                                             |
| E      | A hijacked session registers the attacker's passkey.                                           | Recent step-up for credential changes (ADR 0005; O2)                               | `sensitive-change-without-reauth`                                          |
| T      | A user removes another user's passkey.                                                         | Store calls scoped to tenant and subject (ADR 0002, 0012)                          | `idor-authenticator-removal`                                               |
| E      | Sessions opened before the change stay valid.                                                  | The change revokes the other sessions (ADR 0006, 0007)                             | `sessions-survive-credential-change`                                       |

**Residual risks.** Most passkeys are synced; their security rests on the platform account that syncs them, which
test-cap cannot see. Attestation is not required, so key protection is often `unknown` and such a passkey stops at
AAL2.

## F06: Passkey authentication

Includes conditional-mediation autofill. UV required; origin and RP ID checked; counter and backup flags recorded as
key protection. AAL2 and phishing-resistant; AAL3 only with every ADR 0005 condition.

**Assets:** the AAL2 or AAL3 session. **Boundaries:** B1, B2, B3, B4.

| STRIDE | Threat                                                                   | Stopped by                                                            | Entry                                                        |
| ------ | ------------------------------------------------------------------------ | --------------------------------------------------------------------- | ------------------------------------------------------------ |
| S      | An assertion without UV is counted as AAL2.                              | UV flag checked (ADR 0005, 0016)                                      | `passkey-uv-flag-not-checked`                                |
| S      | An assertion made for another origin is accepted.                        | Expected origin from `APP_ORIGIN` (ADR 0026, 0016)                    | `passkey-origin-from-request`                                |
| S      | An assertion is replayed against a reused challenge.                     | Challenges consumed once (ADR 0002, 0016)                             | `webauthn-challenge-replay`                                  |
| S      | The user handle names a different account than the credential's owner.   | Account from the stored credential; mismatch fails (ADR 0016)         | `passkey-user-handle-mismatch`                               |
| S      | A cloned authenticator signs with a stale counter.                       | Counter recorded; response to regression pending (ADR 0016; O12)      | `webauthn-counter-regression`                                |
| E      | A synced passkey yields AAL3, or a weaker method is forced in its place. | AAL3 conditions; level computed from the evidence produced (ADR 0005) | `passkey-aal3-without-all-conditions`, `assurance-downgrade` |
| R      | Failed ceremonies leave no trace.                                        | OCSF 3002 on every outcome (ADR 0015)                                 | `auth-attempt-not-evented`                                   |

**Residual risks.** Conditional mediation offers whichever passkeys the browser holds for the RP ID; on a shared
device another person's passkey may be offered, and UV is what stops its use. A cloned key with a counter of 0 (most
synced passkeys) cannot be detected by counter.

## F07: Recovery codes: issue and redeem

80-bit codes, stored hashed, each consumed once. Redeeming one yields the recovery-only state.

**Assets:** the codes, the account's recovery path. **Boundaries:** B1, B3, B4.

| STRIDE | Threat                                                      | Stopped by                                                                 | Entry                                              |
| ------ | ----------------------------------------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------- |
| I      | Codes are short or predictable.                             | 80 bits from the random source (ADR 0003, 0007)                            | `weak-secret-generation`                           |
| I      | A database read lets codes be recovered from their hashes.  | argon2id with a per-code salt (ADR 0007)                                   | `recovery-code-weak-storage`                       |
| T      | One code is redeemed twice in parallel, or in another flow. | `consumeOnce`; secrets bound to purpose and account (ADR 0002, 0007)       | `redemption-race`, `one-time-secret-cross-purpose` |
| E      | Redeeming a code yields the account's full level.           | Recovery-only state (ADR 0007; O6)                                         | `recovery-below-account-level`                     |
| E      | Codes issued before a recovery still work after it.         | Completing a recovery revokes outstanding emailed codes (ADR 0007)         | `outstanding-codes-survive-recovery`               |
| T      | A user regenerates or deletes another user's codes.         | Store calls scoped to tenant and subject (ADR 0002, 0012)                  | `idor-authenticator-removal`                       |
| I      | Code comparison leaks through timing.                       | Record chosen by public prefix; secret part checked by argon2id (ADR 0007) | `secret-comparison-timing`                         |
| S      | Saved codes are guessed online.                             | Per-account and account+IP throttles (ADR 0009, 0007)                      | `recovery-code-brute-force`                        |

**Residual risks.** Codes are only as safe as where the user keeps them. Anyone who finds a printed sheet reaches the
recovery-only state.

## F08: Email address confirmation

At least 6 digits, at most 24 hours, single use. Confirms an address; never raises assurance.

**Assets:** the binding between account and address. **Boundaries:** B1, B3, B4, B5.

| STRIDE | Threat                                                                         | Stopped by                                                         | Entry                                              |
| ------ | ------------------------------------------------------------------------------ | ------------------------------------------------------------------ | -------------------------------------------------- |
| S      | A code from another flow, account or address confirms this one.                | Secrets bound to purpose, account and address (ADR 0002, 0021)     | `one-time-secret-cross-purpose`                    |
| S      | An address-change code acts on whoever holds the address when redeemed.        | Code binds account, both addresses and purpose (ADR 0002, 0021)    | `email-change-code-not-bound`                      |
| S      | The 6-digit code is guessed, in sequence or in parallel.                       | Atomic per-code and per-account attempt limits (ADR 0009, 0002)    | `email-code-brute-force`, `otp-attempt-limit-race` |
| S      | An unconfirmed address is trusted elsewhere.                                   | Only confirmed identifiers resolve (ADR 0021)                      | `unverified-identifier-trusted`                    |
| E      | Confirmation counts as authentication.                                         | Email never raises the level (ADR 0021, 0005)                      | `email-raises-assurance`                           |
| T      | The emailed link carries a redirect, or its origin comes from the Host header. | Links built from `APP_ORIGIN`, no redirect target (ADR 0026, 0021) | `email-link-redirect`, `host-header-poisoning`     |
| E      | A hijacked session changes the account's address.                              | Recent step-up for identifier changes (ADR 0005; O2)               | `sensitive-change-without-reauth`                  |
| I      | Codes are short or predictable.                                                | Random source; at least 6 digits (ADR 0003)                        | `weak-secret-generation`                           |
| D      | Confirmation mail is used to flood a victim.                                   | Send throttles; resend countdown (ADR 0009, 0025)                  | `email-send-flooding`                              |

**Residual risks.** Email proves control of a mailbox at one moment, nothing more. A mailbox later lost or recycled
keeps its confirmed status until the user changes it.

## F09: Account recovery by email, including password reset

Same code rules as F08. Leads to the recovery-only state. Completing the recovery revokes the account's other
sessions and outstanding emailed codes; the recovery-only session then ends, and the person signs in with the new
authenticators (ADR 0007, Open 5).

**Assets:** the account itself; this is the usual weakest link. **Boundaries:** B1, B2, B3, B4, B5, B8.

| STRIDE | Threat                                                                                   | Stopped by                                                                            | Entry                                                                                   |
| ------ | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| E      | Recovery yields more than the account's proven evidence, or skips its MFA.               | Recovery-only state (ADR 0007; O6)                                                    | `recovery-below-account-level`                                                          |
| E      | Email recovery counts as authentication.                                                 | Email never raises the level (ADR 0021, 0005)                                         | `email-raises-assurance`                                                                |
| S      | The code is guessed, raced or redeemed twice.                                            | Atomic attempt limits; `consumeOnce` (ADR 0009, 0002)                                 | `email-code-brute-force`, `otp-attempt-limit-race`, `redemption-race`                   |
| S      | A code issued for another purpose or account works here.                                 | Secrets bound to purpose, account and address (ADR 0002, 0007)                        | `one-time-secret-cross-purpose`                                                         |
| S      | Recovery for one address reaches an account holding a look-alike or unconfirmed address. | One normalisation; only confirmed identifiers resolve (ADR 0021, 0002)                | `identifier-normalisation-collision`, `unverified-identifier-trusted`                   |
| T      | The reset link's origin comes from the Host header, or carries a redirect.               | `APP_ORIGIN` only; no redirect target (ADR 0026, 0021)                                | `host-header-poisoning`, `email-link-redirect`                                          |
| I      | A token in a URL leaks through Referer or logs.                                          | Codes typed in, not carried in URLs; `Referrer-Policy` (ADR 0021; O13)                | `token-in-url-leak`                                                                     |
| I      | Replies or timing reveal whether the account exists.                                     | Uniform replies and timing (ADR 0009)                                                 | `user-enumeration-responses`, `user-enumeration-timing`                                 |
| E      | After reset, the attacker's sessions or earlier codes still work.                        | Revoke other sessions and outstanding emailed codes (ADR 0006, 0007)                  | `sessions-survive-credential-change`, `outstanding-codes-survive-recovery`              |
| D      | A reset request locks or changes the account, or floods the inbox.                       | Nothing changes until a valid code; send throttles keyed per /64 too (ADR 0007, 0009) | `reset-request-changes-account`, `email-send-flooding`, `ipv6-rotation-throttle-bypass` |
| E      | The new password is a breached one.                                                      | Blocklist and HIBP (ADR 0010)                                                         | `breached-password-accepted`                                                            |
| I      | The code or new password appears in a security event.                                    | No secret-bearing event field (ADR 0015)                                              | `secret-in-security-event`                                                              |

**Residual risks.** Whoever controls the mailbox reaches the recovery-only state; what that state may then do is O6.
The user learns of a recovery only if test-cap or the app tells them (O14).

## F10: Opt-in email sign-in (code or magic link)

Off by default; turning it on is a deviation in the policy report, and its evidence never satisfies AAL2.

**Assets:** a session that holds no assurance level (ADR 0021, Open 1), accepted only by a requirement that names email
sign-in in its own deviation. **Boundaries:** B1, B2, B3, B4, B5.

| STRIDE | Threat                                                                       | Stopped by                                                      | Entry                                                                 |
| ------ | ---------------------------------------------------------------------------- | --------------------------------------------------------------- | --------------------------------------------------------------------- |
| E      | Email sign-in satisfies an AAL2 requirement.                                 | Email never raises the level (ADR 0021, 0005)                   | `email-raises-assurance`                                              |
| S      | An OAuth state value, or a code from another flow, works as a sign-in token. | Purpose-keyed one-time secrets (ADR 0002, 0021)                 | `oauth-state-reused-as-magic-link`, `one-time-secret-cross-purpose`   |
| S      | The code is guessed, raced or redeemed twice.                                | Atomic attempt limits; `consumeOnce` (ADR 0009, 0002)           | `email-code-brute-force`, `otp-attempt-limit-race`, `redemption-race` |
| D      | A mail scanner's GET consumes the link, or a GET alone signs in.             | GET shows a confirm page; only POST consumes (ADR 0021; O5)     | `magic-link-prefetch-consumes-token`                                  |
| I      | The link's token leaks through Referer, logs or history.                     | `Referrer-Policy`; token consumed on first POST (ADR 0021; O13) | `token-in-url-leak`                                                   |
| D      | Sign-in mail floods a victim.                                                | Send throttles (ADR 0009)                                       | `email-send-flooding`                                                 |

**Residual risks.** Turning it on makes the mailbox a sign-in path for every requirement that names email sign-in in its
deviation; the session holds no level. A link opened on another device than the one that asked signs that other device
in unless the binding in O5 is adopted.

## F11: OIDC sign-in and account linking

`oauth4webapi`; state, nonce and PKCE S256 in a single-use federation transaction; `response_mode=query`; issuer
allowlist. AAL1 unless the trust config maps the issuer's `acr` / `amr`.

**Assets:** the account, its linked identities, the session's level. **Boundaries:** B1, B2, B3, B4, B6.

| STRIDE | Threat                                                                                                                                  | Stopped by                                                                             | Entry                                                                                                                 |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| S      | A forged or mismatched `state` is accepted (login CSRF).                                                                                | Exact comparison against the browser's own transaction (ADR 0006, 0016, 0011)          | `oauth-state-not-compared`, `login-csrf`                                                                              |
| S      | A code is injected without the PKCE verifier, or `plain` PKCE is used.                                                                  | PKCE S256 always (ADR 0016)                                                            | `pkce-downgrade`                                                                                                      |
| S      | An ID token is replayed, unsigned, for another client, or from another issuer's metadata.                                               | Nonce in the transaction; `oauth4webapi` validation; fixed algorithms (ADR 0016, 0008) | `oidc-nonce-replay`, `id-token-unsigned-or-alg-confusion`, `id-token-wrong-audience`, `oidc-issuer-metadata-mismatch` |
| S      | A response from one issuer is processed as another's (mix-up).                                                                          | Issuer recorded in the transaction and matched (ADR 0016, 0008)                        | `oauth-mix-up`                                                                                                        |
| S      | A UserInfo profile from another subject is merged in.                                                                                   | `sub` match checked; identity from the ID token (ADR 0016, 0008)                       | `oidc-userinfo-subject-mismatch`                                                                                      |
| S      | The first sign-in links to an existing account by email, including one pre-registered by an attacker or with `email_verified: "false"`. | No email linking; type-checked claims (ADR 0008; O1)                                   | `oidc-auto-link-to-unverified-account`, `oidc-email-verified-string`, `pre-account-hijack`                            |
| S      | A subject at one issuer signs in to the account linked at another.                                                                      | Links keyed by tenant, issuer and subject (ADR 0008)                                   | `federated-identity-collision`                                                                                        |
| E      | A user registers their own IdP, or a removed issuer's links still work.                                                                 | Static trust config; allowlist checked on every sign-in (ADR 0008, 0012; O11)          | `self-registered-identity-provider`, `removed-issuer-still-signs-in`                                                  |
| I      | A discovery or endpoint URL makes the server fetch internal addresses.                                                                  | No user-supplied URLs; private and link-local blocked (ADR 0008)                       | `federation-discovery-ssrf`                                                                                           |
| E      | An upstream `acr` / `amr`, or a stale `auth_time`, raises the level.                                                                    | Trust-config mapping and maximum authentication age (ADR 0005, 0008)                   | `untrusted-upstream-context-raises-level`, `federated-auth-age-exceeded`                                              |
| T      | A sibling subdomain tosses a `__Host-test-cap-tx` look-alike.                                                                           | `__Host-` prefix (ADR 0006)                                                            | `cookie-tossing`                                                                                                      |
| S      | The transaction is redeemed twice, or used as another kind of secret.                                                                   | `consumeOnce`; purpose-keyed secrets; one key per purpose (ADR 0002, 0022)             | `redemption-race`, `oauth-state-reused-as-magic-link`, `signing-oracle-key-reuse`                                     |
| E      | A hijacked session links the attacker's IdP account.                                                                                    | Recent step-up for linking (ADR 0005; O2)                                              | `sensitive-change-without-reauth`                                                                                     |
| E      | A deprovisioned account signs in through its linked identity.                                                                           | Account status checked before evidence (ADR 0012)                                      | `deprovisioned-account-signs-in`                                                                                      |
| S      | An issuer configured for one tenant signs someone in to another.                                                                        | Issuers accepted only in the tenant that names them (ADR 0012)                         | `cross-tenant-issuer-accepted`                                                                                        |

**Residual risks.** A trusted issuer can sign in as any account linked to it, at up to the level its mapping allows,
which is at most AAL2 (ADR 0005); the trust config is the boundary. Generic OAuth 2.0 sign-in is a stated gap. The
OpenID conformance suite runs at release (phase 9), not on every pull request.

## F12: SAML SP sign-in

`@node-saml/node-saml` 5.2, Node only, last phase, behind its own capability gate (ADR 0028). The POST binding
returns through the `__Host-test-cap-tx` cookie (SameSite=None, 10 minutes, a random id only).

**Assets:** the account, the session's level. **Boundaries:** B1, B2, B3, B4, B6.

| STRIDE | Threat                                                                                                    | Stopped by                                                                                                    | Entry                                                                                                                         |
| ------ | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| S      | Signature wrapping, multiple roots, or identity read from unsigned content.                               | Library past every listed fix; only verified content read (ADR 0028)                                          | `saml-signature-wrapping`, `saml-multiple-root-elements`, `saml-assertion-read-from-unsigned-document`                        |
| S      | A certificate in `KeyInfo`, or an HMAC keyed with the public key, verifies.                               | Pinned IdP certificate; signature algorithm allowlist (ADR 0028)                                              | `saml-keyinfo-certificate-trusted`, `saml-hmac-key-confusion`                                                                 |
| T      | Comments in `DigestValue`, `NameID` or attributes, or extra `SignedInfo` references, change what is read. | Library past the fixes; full canonical text read (ADR 0028)                                                   | `saml-digest-value-comment`, `saml-comment-node-splitting`, `saml-multiple-signedinfo-references`                             |
| T      | Malformed XML is read differently by parser and verifier.                                                 | Library past the fixes; fuzzing of ACS input (ADR 0028)                                                       | `saml-parser-misinterpretation`                                                                                               |
| S      | An assertion meant for another SP, replayed, unsolicited or expired is accepted.                          | Audience, Recipient, Destination; `InResponseTo` bound to the transaction; clock windows (ADR 0028, 0006; O8) | `saml-audience-not-checked`, `saml-response-replay`, `saml-unsolicited-response`, `saml-expired-assertion`, `redemption-race` |
| S      | A detached signature covers a different message than the one parsed.                                      | ACS accepts HTTP-POST with an enveloped signature only (ADR 0028; O8)                                         | `saml-detached-signature-not-bound`                                                                                           |
| I      | An encrypted assertion uses RSA-1.5 or Triple-DES.                                                        | Encryption algorithm allowlist (ADR 0028)                                                                     | `saml-weak-encryption-algorithm`                                                                                              |
| T      | A request value injects XML into an AuthnRequest or SP metadata.                                          | Outbound XML from configuration only (ADR 0028)                                                               | `saml-xml-injection-in-sp-output`                                                                                             |
| D      | Transforms, DEFLATE or quadratic parsing exhaust the server.                                              | Body size limit; POST binding only (ADR 0003, 0028)                                                           | `saml-xml-resource-exhaustion`                                                                                                |
| T      | `RelayState`, or an IdP-supplied URL, becomes a navigation target.                                        | `RelayState` is an opaque transaction id; same-origin targets only (ADR 0028, 0026)                           | `saml-relaystate-open-redirect`, `open-redirect-scheme`                                                                       |
| S      | A NameID at one IdP signs in to the account linked at another; a tenant adds its own IdP.                 | Links keyed by issuer and subject; static trust config (ADR 0008; O11)                                        | `federated-identity-collision`, `self-registered-identity-provider`                                                           |
| S      | An IdP configured for one tenant signs someone in to another.                                             | IdPs accepted only in the tenant that names them (ADR 0012)                                                   | `cross-tenant-issuer-accepted`                                                                                                |
| E      | An `AuthnContextClassRef` raises the level without a mapping.                                             | Trust-config mapping only (ADR 0005, 0008)                                                                    | `untrusted-upstream-context-raises-level`                                                                                     |
| T      | A sibling subdomain tosses the transaction cookie.                                                        | `__Host-` prefix (ADR 0006)                                                                                   | `cookie-tossing`                                                                                                              |

**Residual risks.** XML signature handling has a long advisory history in every Node library, and new classes will
appear; the gate catches only the classes listed. The SameSite=None transaction cookie is sent on cross-site requests
for its 10 minutes; it carries only a random id bound to a single-use record. SAML runs on Node only.

## F13: Step-up

Any ceremony run inside an existing session to add evidence; the token rotates on success.

**Assets:** the session's level. **Boundaries:** B1, B2, B3, B4.

| STRIDE | Threat                                                               | Stopped by                                                                | Entry                                                                   |
| ------ | -------------------------------------------------------------------- | ------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| E      | Evidence from a step-up is applied to another session.               | Challenge bound to the asking session; token rotates (ADR 0005, 0006)     | `step-up-bound-to-other-session`                                        |
| E      | A weaker ceremony satisfies a requirement that needs a stronger one. | Level computed from the evidence produced (ADR 0005)                      | `assurance-downgrade`                                                   |
| E      | The raised level outlives its evidence.                              | Recomputed on every check (ADR 0005)                                      | `expired-evidence-keeps-level`                                          |
| T      | Concurrent rotations leave two valid tokens.                         | `consumeOnce` on the old token (ADR 0002, 0006)                           | `session-rotation-race`                                                 |
| E      | A sensitive change runs on an old step-up, or another path skips it. | Recent step-up required; every issuance computes assurance (ADR 0005; O2) | `sensitive-change-without-reauth`, `alternate-path-skips-second-factor` |

**Residual risks.** Step-up raises assurance for the session, not for one action; anything else that session does in
the same window shares it.

## F14: Session lifecycle

Issue, rotate, idle and absolute expiry, sign-out, session list and remote revoke. Opaque 256-bit tokens, stored as
SHA-256, in `__Host-test-cap` (Secure, HttpOnly, SameSite=Lax, `Path=/`, no Domain).

**Assets:** the session token, the session list. **Boundaries:** B1, B2, B3, B4.

| STRIDE | Threat                                                                        | Stopped by                                                                            | Entry                                                                                                           |
| ------ | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| S      | A planted, guessed or tossed token is used.                                   | Rotation; 256-bit random tokens; `__Host-` prefix (ADR 0006)                          | `session-fixation`, `weak-secret-generation`, `cookie-tossing`                                                  |
| S      | The token travels without TLS or in a URL.                                    | Production refuses HTTP; tokens only in cookies (ADR 0026, 0006)                      | `https-downgrade`, `token-in-url-leak`                                                                          |
| E      | A cached or revoked session still passes, or a cache skips the second factor. | Store read on every request; immediate revoke visibility (ADR 0006, 0002)             | `cached-session-survives-revocation`, `session-cache-skips-mfa`                                                 |
| E      | A session outlives its idle or absolute limit, its evidence, or sign-out.     | Limits per level; recomputed assurance; revoke in store (ADR 0006, 0005)              | `session-timeout-not-enforced`, `expired-evidence-keeps-level`, `sign-out-leaves-session-valid`                 |
| T      | Revoke-all misses a concurrent session; rotation forks.                       | Single-statement revoke; `consumeOnce` rotation (ADR 0002, 0006)                      | `bulk-revoke-race-misses-session`, `session-rotation-race`                                                      |
| T      | A cross-site request signs out or revokes.                                    | CSRF checks on every state-changing route (ADR 0011)                                  | `csrf-state-changing-route`                                                                                     |
| E      | A forged cookie or an id names another user's session, or another tenant's.   | Lookup by token hash; store calls scoped to tenant and subject (ADR 0006, 0002, 0012) | `forged-cookie-names-other-session`, `idor-session-revoke`, `cross-tenant-reference`, `cross-tenant-store-read` |
| S      | A pooled insert hands one user another's new session.                         | Ids from the random source; single statements (ADR 0002; O4)                          | `store-insert-returns-foreign-row`                                                                              |
| S      | A signing key used for something else forges a session-bearing value.         | Sessions are references, not signed values; one key per purpose (ADR 0006, 0022)      | `signing-oracle-key-reuse`                                                                                      |
| I      | A shared cache stores a response with `Set-Cookie`.                           | `no-store` on auth responses (ADR 0026)                                               | `auth-response-cached`                                                                                          |
| E      | A store error answers `allow`.                                                | Errors fail closed (ADR 0003, 0005)                                                   | `fail-open-on-error`                                                                                            |

**Residual risks.** A token copied off the user's device works until it expires or is revoked. Concurrent session
limits are not set by the plan; the session list and remote revoke are the user's control.

## F15: API keys

Hashed, scoped, mandatory expiry. They produce a `service` subject with no assurance level (`test-cap/machine`).

**Assets:** the keys, what their scopes reach. **Boundaries:** B3, B4, B10.

| STRIDE | Threat                                                                  | Stopped by                                         | Entry                                         |
| ------ | ----------------------------------------------------------------------- | -------------------------------------------------- | --------------------------------------------- |
| E      | A request body names another user as the owner.                         | Owner is the session subject (ADR 0013)            | `api-key-owner-from-request`                  |
| E      | A user lists, changes or revokes another user's key.                    | Calls scoped to tenant and owner (ADR 0013, 0012)  | `idor-api-key`, `cross-tenant-reference`      |
| E      | A `service` subject passes a requirement written for people.            | No level on `service` (ADR 0013)                   | `service-subject-satisfies-human-requirement` |
| E      | A key is issued from a session that has not finished its second factor. | Issuance needs computed assurance (ADR 0005, 0013) | `alternate-path-skips-second-factor`          |
| S      | A key without expiry, or past it, works.                                | Mandatory expiry, checked on every use (ADR 0013)  | `expired-or-unexpiring-api-key`               |
| I      | A database read yields usable keys.                                     | Stored hashed; shown once (ADR 0013)               | `api-key-read-at-rest`                        |

**Residual risks.** A leaked key works within its scopes until it expires or is revoked; keys are bearer secrets and
are not sender-constrained (mTLS and workload identity are stated gaps).

## F16: Delegations to agents

Issued from a user's session: short-lived, scoped, revocable. They produce an `agent` subject with `actingFor`
(`test-cap/delegation`).

**Assets:** the user's authority, lent in part. **Boundaries:** B1, B3, B4, B10.

| STRIDE | Threat                                                              | Stopped by                                                | Entry                                |
| ------ | ------------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------ |
| E      | The agent satisfies a requirement through the user's assurance.     | The agent never borrows the human's assurance (ADR 0013)  | `delegation-borrows-human-assurance` |
| E      | The agent uses scopes beyond its grant, or delegates further.       | Scopes fixed at issue; no re-delegation (ADR 0013)        | `delegation-scope-escalation`        |
| E      | The delegation outlives its expiry, its revocation or the user.     | Expiry; revoke; deprovision ends it (ADR 0013, 0012; O10) | `delegation-outlives-grant`          |
| E      | Another user approves, changes or revokes the delegation.           | Calls scoped to the issuing subject (ADR 0013)            | `idor-delegation`                    |
| S      | The user is tricked into approving a delegation they did not start. | Issued only from the user's own session (ADR 0013; O10)   | `delegation-consent-confusion`       |
| E      | A session below its required level issues a delegation.             | Issuance needs computed assurance (ADR 0005, 0013)        | `alternate-path-skips-second-factor` |

**Residual risks.** Within its scopes and lifetime, a delegation does whatever the agent decides; test-cap
authenticates the agent, and access-cap decides what the scopes allow.

## F17: Admin impersonation

A fresh AAL2+ admin session, a reason and a time limit. Flagged on every event; credential changes blocked.

**Assets:** the target user's account and data. **Boundaries:** B3, B4, B7, B9.

| STRIDE | Threat                                                                      | Stopped by                                                                  | Entry                                       |
| ------ | --------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------- |
| E      | Impersonation starts from a stale or weak admin session, or with no reason. | Fresh AAL2+, reason, time limit (ADR 0014)                                  | `impersonation-without-fresh-admin-session` |
| E      | Impersonation outlives its limit or carries into a new session.             | Limit enforced per request; token rotates at start and end (ADR 0014, 0006) | `impersonation-exceeds-grant`               |
| T      | The impersonator changes the user's authenticators or identifiers.          | Credential changes blocked (ADR 0014; O9)                                   | `impersonation-changes-credentials`         |
| R      | Actions appear as the user's own.                                           | Impersonator on the subject and every event (ADR 0014, 0015)                | `privileged-session-unflagged-in-events`    |
| E      | An admin impersonates a user in another tenant.                             | Tenant-scoped admin calls (ADR 0012)                                        | `cross-tenant-reference`                    |

**Residual risks.** Inside the time limit the admin acts as the user. Whether an admin may impersonate at all is
access-cap's decision; test-cap records and limits it.

## F18: Break-glass

Emergency access outside the normal requirements, with a reason and a time limit, flagged on every event and listed
for review.

**Assets:** whatever the grant reaches. **Boundaries:** B3, B4, B7, B9.

| STRIDE | Threat                                                                             | Stopped by                                               | Entry                                    |
| ------ | ---------------------------------------------------------------------------------- | -------------------------------------------------------- | ---------------------------------------- |
| E      | Break-glass is used without a reason, past its limit, or left off the review list. | Reason and limit required; every grant listed (ADR 0014) | `break-glass-exceeds-grant`              |
| T      | The grant is used to change credentials or identifiers.                            | Credential changes blocked (ADR 0014; O9)                | `impersonation-changes-credentials`      |
| R      | Actions under the grant are not attributed to it.                                  | Grant flagged on every event (ADR 0014, 0015)            | `privileged-session-unflagged-in-events` |

**Residual risks.** Break-glass is meant to bypass requirements; review after the fact is the control, and it
depends on someone reading the list.

## F19: Deprovision hook

The call a SCIM server or the app makes: disables the account and revokes every session and delegation.

**Assets:** the account's continued access. **Boundaries:** B4, B9.

| STRIDE | Threat                                                          | Stopped by                                                                  | Entry                                                           |
| ------ | --------------------------------------------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------- |
| E      | Sessions or delegations survive deprovisioning.                 | Deprovision revokes them; session checks read status (ADR 0012, 0006, 0013) | `deleted-account-sessions-survive`, `delegation-outlives-grant` |
| T      | A session written during revocation escapes it.                 | Single-statement revoke (ADR 0002)                                          | `bulk-revoke-race-misses-session`                               |
| E      | The account signs in again through a passkey, OIDC or recovery. | Status checked before any evidence (ADR 0012; O15)                          | `deprovisioned-account-signs-in`                                |
| E      | The hook acts on, or reads, another tenant's account.           | Tenant-scoped store calls (ADR 0012, 0002)                                  | `cross-tenant-reference`, `cross-tenant-store-read`             |

**Residual risks.** test-cap ships the hook, not a SCIM server; deprovisioning is only as timely as the caller. An
API key is revoked only if the hook's caller or the app revokes it (O15).

## F20: Audit: record, checkpoint, verify

Opt-in `test-cap/audit`: records the app writes, chained with HMAC-SHA-256 under `AUTH_AUDIT_KEY`, checkpointed with
Ed25519 under `AUTH_AUDIT_SIGNING_KEY` and exported by the app; `verifyAudit` checks them. Security events (OCSF) are
a separate, always-on stream to `onEvent`.

**Assets:** the integrity of the record of who did what. **Boundaries:** B4, B7.

| STRIDE | Threat                                                     | Stopped by                                                      | Entry                                 |
| ------ | ---------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------- |
| T      | A record is edited, deleted or reordered.                  | HMAC chain; `verifyAudit` (ADR 0020)                            | `audit-record-tampering`              |
| T      | Concurrent appends leave a gap or duplicate.               | `appendAudit` rejects both (ADR 0002, 0020)                     | `audit-sequence-gap-or-duplicate`     |
| T      | Records from another tenant or system are spliced in.      | MAC covers system, tenant, stream and `seq` (ADR 0020, 0012)    | `audit-cross-stream-splice`           |
| R      | An attacker with store and keys rewrites history.          | Exported checkpoints expose it, back to the last one (ADR 0020) | `audit-rewrite-after-last-checkpoint` |
| I      | An event carries a secret, code or full token.             | No secret-bearing field (ADR 0015)                              | `secret-in-security-event`            |
| T      | Control characters in event fields forge or split records. | Structured OCSF objects; `redact` runs first (ADR 0015)         | `log-injection-in-event-fields`       |
| R      | An authentication outcome leaves no event.                 | OCSF 3002 on every outcome (ADR 0015)                           | `auth-attempt-not-evented`            |

**Residual risks.** test-cap sees only what the app records. Anything after the last exported checkpoint can be
rewritten by someone holding the store and the keys; that is the stated limit. Storing security events is the app's
job.

## F21: Default pages and client assets

Server-rendered from the form model: progressive enhancement, strict CSP, no inline script, hashed assets cached
immutably.

**Assets:** the user's browser session on the auth origin. **Boundaries:** B1, B2, B3.

| STRIDE | Threat                                                        | Stopped by                                                                           | Entry                                                                                    |
| ------ | ------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| E      | Error text from the URL, or a stored value, runs as script.   | Error codes mapped to `messages`; one escaping renderer; strict CSP (ADR 0011, 0025) | `reflected-xss-error-page`, `injected-markup-in-pages`                                   |
| T      | A page is framed for clickjacking.                            | `frame-ancestors 'none'` (ADR 0011)                                                  | `clickjacking`                                                                           |
| T      | A form posts cross-site.                                      | CSRF token and Origin check (ADR 0011)                                               | `csrf-state-changing-route`                                                              |
| T      | A page redirects off-site or to a script URL.                 | Same-origin relative paths only (ADR 0026)                                           | `open-redirect-protocol-relative`, `open-redirect-origin-prefix`, `open-redirect-scheme` |
| T      | Links or assets are built from the Host header.               | `APP_ORIGIN` only (ADR 0026)                                                         | `host-header-poisoning`                                                                  |
| T      | An asset is sniffed, mistyped or swapped under a stable name. | Hashed names; `nosniff`; exact types (ADR 0025, 0011)                                | `asset-substitution-or-sniffing`                                                         |
| I      | A shared cache keeps a page with account data.                | `no-store` (ADR 0026)                                                                | `auth-response-cached`                                                                   |
| I      | Page messages or errors reveal an account or internal detail. | Uniform messages; fixed public error bodies (ADR 0009, 0003)                         | `user-enumeration-responses`, `secret-in-response`                                       |

**Residual risks.** The app's own pages, and any app script loaded on the auth origin, are outside this CSP. A
replaced `messages` string is the app's text.

## F22: Adapter transport and deny by default

Adapters convert framework requests to bytes and back; the core does all parsing. Deny by default protects every
route not listed as public.

**Assets:** the core's view of the request; every protected route. **Boundaries:** B1, B3.

| STRIDE | Threat                                                                                                               | Stopped by                                                                                                                                                                                          | Entry                                                                               |
| ------ | -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| E      | A protected route is reached through `//`, a trailing slash, case, encoding or another method.                       | Ambiguous paths refused with a 400 for every request, never normalised; public paths match clean raw paths only, exactly or by explicit wildcard; deny by default for every method (ADR 0003, 0024) | `double-slash-path-bypass`, `deny-by-default-bypass`                                |
| T      | The adapter and core disagree on headers, cookies, path or body.                                                     | Adapters convert bytes only; the adapter conformance suite (ADR 0003, 0024)                                                                                                                         | `adapter-core-parsing-differential`                                                 |
| T      | An app body parser rewrites the body before the core sees it.                                                        | Raw stream read; pre-parsed body refused (ADR 0003, 0024)                                                                                                                                           | `upstream-body-parser-changes-core-view`                                            |
| T      | The request sets fields the route does not declare.                                                                  | Declared fields only (ADR 0003)                                                                                                                                                                     | `mass-assignment-server-owned-fields`                                               |
| E      | Next.js `proxy` is the only check.                                                                                   | Authoritative server helpers; `proxy` for redirects only (ADR 0024)                                                                                                                                 | `next-proxy-treated-as-protection`                                                  |
| S      | A forwarded header or the Host header is trusted.                                                                    | `trustedProxies`; `APP_ORIGIN` (ADR 0009, 0026)                                                                                                                                                     | `spoofed-forwarded-for`, `host-header-poisoning`                                    |
| T      | A cross-site request reaches a state-changing route.                                                                 | CSRF checks in the core (ADR 0011)                                                                                                                                                                  | `csrf-state-changing-route`                                                         |
| D      | Oversized or deeply nested input exhausts the parser.                                                                | Body limit before parsing; fuzzing (ADR 0003)                                                                                                                                                       | `request-parser-resource-exhaustion`                                                |
| D      | A client floods the auth routes, or respells a path so the request limiter keys it apart while the route still runs. | A request limit on every route, keyed by the route the raw path names (ADR 0003, 0009)                                                                                                              | `request-flooding`, `limiter-path-bypass`                                           |
| E      | Startup with dev defaults, missing or default secrets, or HTTP.                                                      | Missing `APP_ENV` means production (ADR 0026, 0022)                                                                                                                                                 | `production-runs-with-dev-defaults`, `missing-or-default-secret`, `https-downgrade` |
| I      | An error returns internal configuration.                                                                             | Fixed public error bodies (ADR 0003)                                                                                                                                                                | `secret-in-response`                                                                |
| E      | An error answers `allow`.                                                                                            | Fail closed (ADR 0003, 0005)                                                                                                                                                                        | `fail-open-on-error`                                                                |
| S      | A key shared across purposes signs something the adapter forwards.                                                   | One key per purpose (ADR 0022)                                                                                                                                                                      | `signing-oracle-key-reuse`                                                          |

**Residual risks.** A route the app lists as public is public. Edge runtimes are not claimed. A framework that
rewrites requests before the adapter runs (a platform proxy, a rewrite rule) is outside the conformance suite.

## Open

Questions the plan leaves unsettled, each with a recommendation that is a provisional default until the owner decides.
The owner's copy of each question lives in `Dev/auth-cap-design/questions-for-owner.md`, outside this repository.

- **O1. Account linking (ADR 0008).** When may an OIDC or SAML identity link to an existing account? Recommendation:
  never by a matching email, verified or not; only from a session signed in to that account at its level, after a
  recent step-up, as OWASP's "Secure Federated Account Linking" describes. A first sign-in with an unknown issuer and
  subject never attaches to an existing account.
- **O2. Re-authentication for sensitive changes (ASVS 7.5.1).** Which requirement guards adding or removing an
  authenticator, changing an identifier, linking or unlinking, and revoking other sessions? Recommendation: a
  built-in requirement, `account.credentials`, of AAL2 with a ceremony at most 10 minutes old, configurable, listed in
  the policy report (the same requirement as `specs/requirements.md` Open 8).
- **O3. Recovery-code hashing (ASVS 6.5.2).** Settled: ADR 0007 section 1 stores each code as argon2id with its own
  salt, selected by a short non-secret prefix so a redemption runs one hash.
- **O4. MySQL has no `RETURNING`.** MySQL 8.4 does not support `UPDATE … RETURNING` (MariaDB does), which the plan
  names as the single-statement form. Recommendation: on MySQL, `consumeOnce` is a conditional `UPDATE` whose
  affected-row count decides; ids are generated by test-cap and never read back with `LAST_INSERT_ID()`; the
  conformance kit proves it under concurrency.
- **O5. Email sign-in (F10) details.** Lifetime, binding and link prefetch. Recommendation: at most 10 minutes (ASVS
  6.5.5 for out-of-band codes); bound to the browser that asked, as ASVS 6.6.2 asks; a GET shows a confirm page and
  only a POST consumes the token.
- **O6. What email recovery restores (ADR 0007).** The plan says recovery never yields more than the account's proven
  evidence, but not what the recovery-only state may do for an AAL2 account recovered by email alone. Whoever holds
  the mailbox can otherwise enrol their own authenticator. Recommendation: a saved recovery code, or email plus a
  remaining authenticator, may enrol at once; email alone may enrol only after a notice to every confirmed address
  and a waiting period (24 hours) that any existing authenticator can cancel.
- **O7. Unconfirmed sign-ups.** Recommendation: an unconfirmed sign-up holds no uniqueness claim on its identifier,
  expires with its 24-hour code, and is discarded when another sign-up confirms the address first.
- **O8. SAML scope (ADR 0028).** Recommendation: the ACS accepts only the HTTP-POST binding; only SP-initiated
  responses with a matching `InResponseTo` are accepted; single logout is not in the first build.
- **O9. What impersonation and break-glass block.** Settled: the glossary's credential change covers identifier
  changes and linking or unlinking identities, and ADR 0014 section 4 blocks every credential change.
- **O10. Delegation consent and lifetime.** Recommendation: issuing a delegation goes through a step-up page that
  shows the agent and scopes from server data; a delegation never outlives the issuing session's absolute expiry, and
  ends when that session is revoked or signs out.
- **O11. Per-tenant IdP configuration.** May a tenant admin add an issuer at run time? Recommendation: no. The trust
  config is deployment configuration reviewed in code, with tenant-scoped entries.
- **O12. WebAuthn counter regression.** Recommendation: when a non-zero counter does not increase, reject the
  ceremony and emit a security event; counters that stay at 0 (most synced passkeys) are not checked.
- **O13. Referrer policy.** Recommendation: `Referrer-Policy: no-referrer` on every auth response and default page,
  alongside the CSP (ADR 0011).
- **O14. Notifications (ASVS 6.3.7).** Recommendation: test-cap sends, through `sendEmail`, a notice to every
  confirmed address after a password reset, a recovery, an authenticator added or removed, an identifier change, and
  a link or unlink.
- **O15. Deprovision's phase and reach.** The build order does not name the phase that builds F19, nor whether it
  revokes API keys. Recommendation: phase 4, with revocation; it also revokes the account's API keys.
- **O16. Network access during attestation.** Recommendation: registration makes no network requests (no CRL or AIA
  fetch); trusted roots and revocation data are configured locally and updated with the package.
