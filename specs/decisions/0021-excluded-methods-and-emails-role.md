# 0021: Excluded methods and email's role

## Status

Accepted (2026-11-15). Implemented in phase 5 (email confirmation, recovery and opt-in email sign-in); the exclusions
hold from phase 2. Flows: F08 (email address confirmation), F09 (account recovery by email), F10 (opt-in email
sign-in). Pinned by:

- `test/surface/excluded-methods.test.ts`
- `test/assurance/email-never-raises.test.ts`
- `test/assurance/email-sign-in-cannot-satisfy-aal2.test.ts`
- `test/report/email-sign-in-deviation.test.ts`
- `test/email/confirmation-code-limits.test.ts`
- `test/recovery/email-code-limits.test.ts`
- `test/attacks/one-time-secret-cross-purpose.test.ts`
- `test/attacks/redemption-race.test.ts`
- `test/attacks/oauth-state-reused-as-magic-link.test.ts`
- `test/attacks/host-header-poisoning.test.ts`
- `test/attacks/identifier-normalisation-collision.test.ts`
- `test/attacks/unverified-identifier-trusted.test.ts`
- `test/attacks/email-raises-assurance.test.ts`

The recommendations under Open are provisional defaults until the owner decides.

## Context

Owner requirement 5 asks for every secure, free authentication method from the start. Some common methods fail one of
those two words, and email is used everywhere as if it were an authenticator when NIST SP 800-63B-4 says it is not.

The facts this decision rests on (research note, "NIST SP 800-63B-4"):

- §3.1.3.1: "Email SHALL NOT be used for out-of-band authentication." Codes that confirm an email address, or that are
  issued as recovery codes, "are not authentication processes".
- Email confirmation codes: at least 6 digits, valid at most 24 hours, invalidated on use (800-63A-4 §3.8). Recovery
  codes issued by email: at least 6 digits, valid at most 24 hours (§4.2.1.2).
- PSTN (SMS and voice) is a restricted authenticator.

[ADR 0005](0005-policy-and-evidence-based-assurance.md) owns how evidence becomes an assurance level. This decision says
which methods exist at all and what email evidence is worth inside that model.

## Decision

### 1. SMS, voice and push are excluded

test-cap offers no SMS, voice or push method, and its configuration has no place to turn one on.

| Method | Why it is excluded                                                                               |
| ------ | ------------------------------------------------------------------------------------------------ |
| SMS    | A restricted authenticator under 800-63B-4 (PSTN), open to SIM swap, and paid per message.       |
| Voice  | The same PSTN restriction, and paid per call.                                                    |
| Push   | Needs a mobile app and a push service the owner would run, and invites approval-fatigue attacks. |

Why: each fails "secure", "free" or both, and every account already has a phishing-resistant option (passkeys) and a
free second factor (TOTP).

Override: none. An app that must send SMS does so outside test-cap, and that channel raises no assurance.

### 2. Email confirms addresses and carries recovery codes

Email has two jobs:

- **Address confirmation** (F08): a code of at least 6 digits, valid at most 24 hours, consumed once through the
  `consumeOnce` atomic operation.
- **Account recovery** (F09): an issued recovery code under the same limits. [ADR 0007](0007-recovery.md) owns what a
  recovered account may do; a recovery never yields more than the account's proven evidence.

Email links are built from `APP_ORIGIN`, never from the `Host` header
([ADR 0026](0026-strict-defaults-and-deployment-mode.md)).

Why: these are the uses 800-63B-4 permits, and both need a single-use code that a race cannot redeem twice.

Override: the app supplies `sendEmail`, a `SendEmail` function that receives each `EmailMessage`, and the message
text. The code length, lifetime and single use are fixed.

### 3. Email never raises the assurance level

An email code or link produces no `AuthenticationEvidence` ([ADR 0005](0005-policy-and-evidence-based-assurance.md)),
the same rule recovery follows ([ADR 0007](0007-recovery.md)). The fact that an address was confirmed, or that an
email sign-in happened, is recorded on the account or the session and in a security event, never as evidence. A
session's assurance after confirming an address or redeeming an email recovery code is what its other, still-valid
evidence supports.

Why: §3.1.3.1 says email is not an authentication process. Counting it would let anyone who controls an inbox reach
whatever level email was counted for.

Override: none.

### 4. Email sign-in is opt-in and a reported deviation

Email sign-in (F10), by code or magic link, is off by default. Turning it on is a deviation that the policy report
lists. Even turned on, an email sign-in can never satisfy an AAL2 requirement, so under the default policy, where every
requirement is AAL2, an email sign-in alone opens nothing a requirement protects.

Why: some apps want a password-free start for low-risk pages. The deviation makes that choice visible, and section 3
keeps it from weakening anything the policy protects at AAL2.

Override: the app turns it on in the policy, and the policy report shows the line.

### 5. Stated gaps

These are not built and are listed as gaps, not exclusions:

- **Generic OAuth 2.0 sign-in** (GitHub-style, with no ID token). OIDC covers federation; plain OAuth 2.0 has no
  standard identity assertion to verify. It left the first build in the review triage.
- **A SCIM server.** The `deprovision` hook ships (F19, [ADR 0012](0012-tenancy.md)), so an app's own SCIM endpoint can
  revoke sessions.
- **mTLS and workload identity.** Machine callers use API keys
  ([ADR 0013](0013-human-machine-and-delegation-separation.md)).

Why: each is a real need, but none is required for the first build, and each would add a protocol surface that needs
its own gate.

### 6. One identifier normalisation, and only confirmed identifiers resolve

An email identifier is normalised once, by one function in the core, wherever it enters: sign-up, sign-in, recovery,
address change and linking. A value with surrounding whitespace, a control character or an invalid address form is
refused, never trimmed or repaired. Stores compare the normalised value byte for byte (binary collation in the
migrations, [ADR 0002](0002-store-port-and-atomic-operations.md)). The exact rules are Open 3.

Only a confirmed identifier resolves to an account. Sign-in, recovery and linking look an account up by confirmed
identifiers only; an identifier saved but never confirmed resolves to nothing, and the reply is the one any unknown
identifier gets ([ADR 0009](0009-abuse-and-proxy-trust.md)).

Why: two spellings of one address that reach two accounts, or one account through a look-alike, are the
normalisation-collision class, and a database collation that folds case or padding re-creates it below test-cap. An
identifier nobody has proved is the attacker's word, so it must not open recovery or sign-in for whoever typed it.

Override: none.

## Consequences

- An account's assurance never depends on who can read its inbox.
- An app that wants email sign-in gets it, and the policy report says so.
- Apps that need SMS for reach must build it themselves, with no assurance from test-cap.

## Limits

- **Email delivery is the app's.** test-cap builds the message; the app's `sendEmail` sends it. Whether it arrives,
  and who else can read it, is outside test-cap.
- **An inbox takeover still lets an attacker run account recovery.** ADR 0007 bounds what recovery yields; this
  decision only stops email from raising the level.
- **The gaps in section 5 are unmet requirements**, not decided non-goals.

## Open

1. **What a session from email sign-in alone holds.** The plan says email sign-in "cannot satisfy AAL2" but not whether
   it satisfies AAL1, and NIST says it is not authentication at all. Recommendation: it holds no assurance level, and
   only a requirement that names email sign-in in its own deviation line accepts it.
2. **Magic links and mail scanners.** Link scanners fetch URLs in incoming mail, and a single-use link consumed by a
   `GET` is spent before the person clicks it. Recommendation: the link opens a confirmation page, and only that page's
   `POST` consumes the token.
3. **The normalisation rules.** Recommendation: Unicode NFC over the whole address, the whole address lower-cased
   (providers treat the local part case-insensitively in practice, and two accounts differing only in case are a
   collision risk), and the domain converted to its IDNA A-label form.
