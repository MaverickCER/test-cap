# 0007: Recovery never yields more than the account's proven evidence

## Status

Accepted (2026-11-15). Implemented in phase 4 (recovery codes, the recovery-only state, and the recovery attack
tests) and phase 5 (recovery by email, including password reset).

Answers [handoff question](../../GLOSSARY.md) 7 (account recovery), partly: admin-assisted recovery is left open (see
Open).

Tests built in phase 4:

- `test/recovery/recovery-codes.test.ts` (80 bits from the `RandomSource`; only argon2id hashes stored; shown once; a
  code works once; a new set invalidates the old one);
- `test/recovery/recovery-flow.test.ts` (codes need a session at the default requirement or a recovery-only one;
  redeeming yields a recovery-only session with no level and revokes the account's other sessions; `auth.require`
  answers `recovery-only` for every requirement; only the replacement actions succeed; the account's address is told
  as the recovery starts; finishing signs the person out);
- `test/attacks/recovery-below-account-level.test.ts` (a recovered AAL2 account's session holds no level and reaches
  nothing that needs one);
- `test/attacks/sessions-survive-credential-change.test.ts` (recovery and a replaced password leave no other session
  signed in);
- `test/attacks/redemption-race.test.ts` (parallel redemptions of one recovery code, exactly one wins);
- `test/attacks/recovery-code-brute-force.test.ts` (saved recovery codes are throttled per ADR 0009);
- `test/attacks/recovery-code-weak-storage.test.ts` (a stored code is an argon2id hash with its own salt).

Planned for phase 5, with recovery by email:

- `test/recovery/email-code-limits.test.ts` (at least 6 digits, at most 24 hours, invalidated on use);
- `test/attacks/outstanding-codes-survive-recovery.test.ts` (an emailed recovery code issued before a completed
  recovery no longer works);
- `test/assurance/recovery-yields-no-assurance.test.ts` (no recovery path produces evidence or a level);
- `test/attacks/email-code-brute-force.test.ts` (email codes are throttled per ADR 0009).

The recommendations under Open are provisional defaults until the owner decides.

Amended 2026-11-24: an account holds one live set of recovery codes. A new set becomes current by one
compare-and-set, so of parallel requests one wins, and the old set works until the switch. Redeeming a code and the
recovery password change each run in one transaction where the store has them
(`test/recovery/recovery-codes.test.ts`, `test/recovery/recovery-transactions.test.ts`). So the Limits bullet "Two
sets made at once can both stay partly live" no longer holds. `test/attacks/email-code-brute-force.test.ts`, listed
under phase 5, exists already and covers the confirmation code.

## Context

Recovery is usually the weakest link: a strong sign-in is worth little if a weaker path replaces the authenticators
behind it. The handoff asked that recovery not drop below the account's assurance level, and asked about recovery
codes, admin-assisted recovery and its audit trail (question 7).

NIST SP 800-63B-4 frames recovery as something other than authentication. §3.1.3.1 notes that codes sent to confirm
an email address, or issued as recovery codes, "are not authentication processes". It sets the codes' strength:

- saved recovery codes: "at least 64 bits from an approved random bit generator", "stored ... in hashed form using an
  approved one-way function" (§4.2.1.1);
- issued recovery codes: "at least six decimal digits (or equivalent)", valid at most 24 hours when sent by email
  (§4.2.1.2).

The plan restates the handoff's aim in the form test-cap can enforce: a password reset or recovery never yields more
than the account's proven evidence.

## Decision

### 1. Recovery codes are 80-bit and stored hashed

A user with an AAL2 session can generate a set of saved recovery codes. Each holds 80 bits from the `RandomSource`
(ADR 0003). The store keeps only a salted password hash of each code (argon2id at the ADR 0018 cost, one salt per
code), so each code is shown once, when generated. Each code carries a short non-secret prefix that names its row, so
redeeming one costs a single hash. Generating a new set invalidates the old one, and only once every new code is
hashed, so a busy or failing hasher leaves the old set working. Redemption uses `consumeOnce` (ADR 0002), so a code
works once even under parallel requests.

Why: 80 bits clears NIST's 64-bit floor with room to spare. Because it is below 112 bits, 800-63B-4 §3.1.2.2 and ASVS
6.5.2 require a salted password-hashing scheme rather than a plain hash, so a database copy cannot be brute-forced
cheaply.
`consumeOnce` closes the redemption race that Better Auth's OTP advisory (`2f9c-7xj7-gh55`) shows.

### 2. Recovery by email uses issued codes

Account recovery by email, including password reset (flow F09), sends an issued recovery code: at least 6 digits,
valid at most 24 hours, invalidated on use, built into a message whose links come from `APP_ORIGIN`, never from the
`Host` header (ADR 0026). Guessing is bounded by the throttling of ADR 0009.

Why: these are the §4.2.1.2 limits. A 6-digit code can be guessed by trial, so its safety rests on single use, expiry
and throttling, each of which is tested.

### 3. Recovery yields a recovery-only state, never assurance

Redeeming a recovery code, or an email recovery code, produces no `AuthenticationEvidence` and no level. It moves the
session into the recovery-only state. In that state `auth.require` answers `recovery-only` for every requirement (ADR
0005), and the session can only replace the account's authenticators: set a new password, enrol a passkey or a TOTP
secret, and generate new recovery codes. Assurance comes only from an authentication ceremony with the new
authenticators afterwards.

Why: recovery proves control of a code or a mailbox, not possession of the lost authenticator. Giving it no level
means an attacker who holds a mailbox gets exactly what the mailbox proves, and the level rules of ADR 0005 decide
everything after.

### 4. Recovery revokes the account's other sessions and emits events

Completing a recovery is a credential change: it revokes the account's other sessions (ADR 0006), revokes every
outstanding emailed recovery code of the account with `revokeByOwner` (ADR 0002), and emits a security
event (OCSF User Management: Password Reset for a reset, Enable or Disable MFA Factors for authenticator changes; ADR
0015).

Why: a person who recovers an account usually suspects someone else has it. Their sessions must end with the old
authenticators, and a second emailed code sitting in the same mailbox must not open a second recovery. Saved recovery
codes stay valid apart from the one redeemed; generating a new set during recovery invalidates the old set
(section 1).

## Consequences

- Recovery cannot be a shortcut to a high level. An AAL3 account recovered by email returns to AAL3 only after a new
  ceremony with an authenticator that meets ADR 0005's AAL3 conditions.
- The recovery-only outcome lets every adapter route a recovering person to the replacement pages, never to the app.
- Recovery codes and email codes share one store guarantee and one throttle, so their races and guessing are tested
  once.

## Limits

- **Holding the mailbox can still replace every authenticator.** Section 3 caps what recovery yields, but as written
  an attacker with the mailbox can enrol their own authenticators and then reach AAL2 with them. The handoff's aim,
  "recovery must not drop below the account's assurance level", is therefore only partly met. See Open.
- **Admin-assisted recovery is not designed.** See Open.
- **Recovery code format and count** are not fixed by the plan. See Open.
- **Two sets made at once can both stay partly live.** Each request revokes the old set and then stores its own ten
  codes, so of two parallel requests for one account, codes of both sets can survive, and either reply can list codes
  the other revoked. Serialising the replacement per account needs a generation record that redemption checks; it is a
  follow-up. Hashing first keeps that window to the ten store writes.
- **test-cap does not deliver email.** It builds the message and calls the app's `sendEmail`; delivery, and the
  security of the mailbox, are outside test-cap.

## Open

1. **Email recovery for accounts with several authenticators.** Recommendation: an email recovery code alone may
   replace one lost authenticator only together with another authenticator the account still holds (for example, the
   password to replace a lost TOTP secret); replacing every authenticator needs a saved recovery code. Allowing email
   alone to replace everything stays possible as a deviation listed in the policy report.
2. **Admin-assisted recovery.** Recommendation: not in the first build. An administrator can revoke sessions and
   start an email recovery for the user, but cannot set credentials. Each step is a security event and, with
   `test-cap/audit`, an audit record. Impersonation and break-glass (ADR 0014) are not recovery paths.
3. **Recovery code format.** Recommendation: 10 codes per set, each 16 base32 characters (80 bits) shown in groups of
   four, plus the non-secret row prefix. Hashing is decided in section 1 (argon2id, per-code salt). _Built in phase 4:
   a 6-character prefix and a 16-character secret, shown as `XXXXXX-XXXX-XXXX-XXXX-XXXX`._
4. **Default lifetime of an email recovery code.** The plan sets 24 hours as the ceiling. Recommendation: 15 minutes by
   default, configurable up to 24 hours.
5. **How a session leaves recovery-only.** Recommendation: when the person finishes replacing authenticators, the
   recovery-only session ends and they sign in again with the new ones, so the evidence comes from a fresh
   authentication ceremony and not from enrolment. _Built in phase 4: `POST /auth/recovery/finish`._
6. **Notifying the account.** Recommendation: every completed recovery sends a notice to the account's confirmed email
   address, so a recovery the owner did not start is visible to them. _Built in phase 4, earlier than recommended: the
   notice goes when a code is redeemed, because a recovery that never finishes could otherwise replace credentials
   unseen._
