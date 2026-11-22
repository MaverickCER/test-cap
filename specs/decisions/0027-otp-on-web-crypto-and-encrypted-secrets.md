# 0027: OTP on Web Crypto and encrypted secrets

## Status

Accepted (2026-11-15). Implemented in phase 3 (password plus TOTP in the first slice). Flows: F03 (TOTP enrolment) and
F04 (TOTP verification). Pinned by:

- `test/otp/hotp-rfc4226-vectors.test.ts`
- `test/otp/totp-rfc6238-vectors.test.ts`
- `test/otp/truncation-and-counter.test.ts`
- `test/attacks/totp-code-replay.test.ts`
- `test/crypto/secret-encryption.test.ts`
- `test/crypto/key-rotation.test.ts`
- `test/attacks/totp-secret-read-at-rest.test.ts`

The recommendations under Open are provisional defaults until the owner decides.

## Context

Owner requirement 1: build on established libraries, and never hand-write protocols or cryptography. TOTP needs an
HOTP implementation, and the obvious library is gone: Oslo (`@oslojs/otp`, `@oslojs/crypto`, `@oslojs/webauthn`) has
been deprecated since 2026-07-29 (research note, "Libraries").

HOTP (RFC 4226) is an HMAC over a counter followed by a fixed truncation; TOTP (RFC 6238) is HOTP with the counter
taken from the time. The cryptography is the HMAC, and every runtime test-cap supports has it in the global
`crypto.subtle`.

A TOTP secret is a shared key: whoever reads it from the database can produce valid codes. NIST SP 800-63B-4 §3.1.4.2
says OTP keys "SHALL be strongly protected against unauthorized disclosure by access controls"; it does not require
encryption. §3.1.4.1 requires a key strength of at least 112 bits.

## Decision

### 1. HMAC from Web Crypto; test-cap's module only truncates and counts

HOTP and TOTP are built on Web Crypto HMAC (`crypto.subtle.sign`). test-cap's own module computes the counter (from
the injected clock, for TOTP) and applies RFC 4226's dynamic truncation. It contains no hash or MAC code.

Why: this is the smallest surface that is not a library, and it holds no cryptography. Using the injected clock makes
every time step reachable in tests and lets mutation testing kill time-dependent mutants.

Override: none.

### 2. The RFC test vectors pin it

The HOTP module is checked against the RFC 4226 Appendix D vectors and TOTP against the RFC 6238 Appendix B vectors,
in every runtime the table in [ADR 0023](0023-runtime-support-per-capability.md) claims.

Why: the vectors are the specification's own answer; a module that passes them computes the same codes as every
authenticator app.

### 3. A time step is accepted at most once

After a code is accepted for an authenticator, a second code for the same time step is rejected, even if it is correct.
The authenticator's record stores the last accepted step. A verification reads the record, checks that the code's step
is later than the stored one, and writes the new step with the compare-and-set `update(..., expectedVersion, ...)`
([ADR 0002](0002-store-port-and-atomic-operations.md)). Of two concurrent requests with the same code, one write
succeeds and the other gets `conflict` and fails, so both cannot succeed.

Why: a code seen over a shoulder or through a phishing proxy is otherwise good for the rest of its step. `consumeOnce`
takes a record that already exists, and nothing exists for a step until it is used, so the guarantee needs a
compare-and-set on the stored last step instead. The race is a
Better Auth advisory class (OTP race) and has its own attack test.

Override: none.

### 4. TOTP secrets are encrypted at rest with AES-GCM under `AUTH_ENCRYPTION_KEY`

Each TOTP secret is encrypted with AES-GCM from Web Crypto before it reaches the store, under `AUTH_ENCRYPTION_KEY`.
The ciphertext records the key id it was encrypted with. Rotation adds a new current key; older keys stay available
to decrypt until no ciphertext names them. The variable's format is [ADR 0022](0022-environment-variables.md)'s.

Why: access controls alone fail the moment a backup, a replica or a SQL injection exposes the table. Encrypting means a
database dump without the key yields no usable secret.

Override: the app supplies and rotates the key.

### 5. Encryption is test-cap's stricter choice, not a NIST claim

The docs and the policy report say that NIST requires access controls on OTP secrets (§3.1.4.2) and that encryption
goes beyond it. They do not say NIST requires encryption.

Why: stating a requirement NIST does not make would be an over-claim, and ADR 0019 (section 5) holds every document to
what test-cap's own evidence shows.

### 6. At most five TOTP authenticators per account, and one enrolment waiting

An account holds at most 5 confirmed, unrevoked TOTP authenticators; beginning a sixth enrolment answers
`409 too-many-authenticators`, from the API and the default enrolment page. Beginning an enrolment removes any other
enrolment of the account still waiting for its code, so at most one waits; the page that shows a setup key once
therefore begins a new enrolment after a wrong code rather than showing the key again.

Why: every TOTP verification reads the account's authenticators, so without a limit a signed-in attacker could grow
that list, and the store, without end (`test/attacks/totp-authenticator-flood.test.ts`). Five covers a phone, a spare
and a password manager with room to replace one. Two enrolments begun at the same moment can each pass the check, so
the limit can be passed by as many enrolments as race; the next enrolment after that is refused.

## Consequences

- No OTP library is a dependency, and no deprecated one is.
- A store compromise without `AUTH_ENCRYPTION_KEY` does not reveal TOTP secrets.
- Losing every copy of `AUTH_ENCRYPTION_KEY` makes every TOTP enrolment unusable; those accounts recover through ADR
  0007 and enrol again.
- Each TOTP verification costs one decryption and one atomic operation.

## Limits

- **HOTP is a building block, not a method.** No counter-based authenticator can be enrolled.
- **An attacker with the store and the key** reads every secret; encryption moves the target from the database to the
  key.
- **A code phished and relayed within its step** before the real person uses it is accepted. TOTP is not
  phishing-resistant, which is why [ADR 0005](0005-policy-and-evidence-based-assurance.md) counts it as AAL1 alone and
  offers passkeys.
- **Recovery codes and passwords are hashed, not encrypted** (ADRs 0007 and 0010); this decision covers OTP secrets
  only.

## Open

1. **TOTP parameters.** The plan does not fix them. Recommendation: SHA-1, 6 digits, a 30-second step and one step of
   drift either side, which every common authenticator app accepts; a secret of 160 bits from the injected random
   source, above §3.1.4.1's 112-bit floor.
2. **Earlier steps after a later one.** The plan rejects a replay of the same step. RFC 6238 §5.2 goes further.
   Recommendation: store the last accepted step per authenticator and reject any step at or before it, which also
   stops a code from the previous step being used after a newer one.
3. **Binding ciphertext to its row.** Without it, an attacker who can write the table could swap one account's
   encrypted secret into another's. Recommendation: pass the tenant, user and authenticator id as AES-GCM additional
   data, and use a fresh 96-bit random IV for each encryption.
4. **How rotation re-encrypts.** Recommendation: re-encrypt a secret under the current key on its next successful
   verification, and provide an admin call that re-encrypts the rest, so an old key can be retired on a known date.
