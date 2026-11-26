# 0020: Audit integrity model

## Status

Accepted (2026-11-15). Implemented in phase 8. Flow: F20 (audit: record, checkpoint, verify). Pinned by:

- `test/audit/canonical-json.test.ts`
- `test/audit/chain.test.ts`
- `test/audit/key-rotation.test.ts`
- `test/store/conformance/append-audit.test.ts`
- `test/audit/checkpoint-signing.test.ts`
- `test/audit/checkpoint-export.test.ts`
- `test/audit/verify-tamper.test.ts`
- `test/attacks/audit-record-tampering.test.ts`
- `test/attacks/audit-rewrite-after-last-checkpoint.test.ts`
- `test/audit/session-timeline.golden.test.ts`
- `test/audit/access-report.golden.test.ts`
- `test/audit/privacy.test.ts`
- `test/audit/retention-and-legal-hold.test.ts`

The recommendations under Open are provisional defaults until the owner decides.

Amended 2026-11-24: the sentence under Consequences that maps audit to HIPAA §164.312(b) and PCI DSS v4
requirement 10 is withdrawn. It stays below as the record of what was accepted. test-cap makes no compliance claim
(ADR 0017, ADR 0019), and `test/docs/no-regulation-named.test.ts` fails if any other doc names a regulation. Audit is
planned for phase 8.

## Context

The owner wants an optional audit trail for healthcare and fintech apps (owner requirement 4): who signed in to which
system, when, and what happened during the session. Such a trail is only worth keeping if a later reader can tell
whether it was changed.

Two records already exist and are kept apart from this one. Security events ([ADR 0015](0015-security-events.md)) are
always on, go to the app's `onEvent` sink as OCSF 1.9.0, and are stored by the app; test-cap keeps no copy and promises
nothing about their integrity. The audit trail is the opt-in record whose integrity test-cap does promise, within the
limits below.

Three facts shape the design:

- A hash chain alone proves order and content only to someone who trusts the last hash. Whoever controls the database
  can recompute every hash after an edit.
- A keyed chain (HMAC) stops a database-only attacker from recomputing links, but anyone holding the key can.
- A signature whose public key and signed values live outside the database fixes the chain at points an insider
  cannot move without also controlling that outside storage.

The plan composes all three. Ed25519 and HMAC-SHA-256 come from the global `crypto.subtle`, which was tested on Node
22.23, Bun 1.3.14 and Deno 2.9.4 (research note, "Platform").

## Decision

### 1. The audit trail is opt-in and lives in `test-cap/audit`

An app that never imports `test-cap/audit` stores no audit records and needs neither audit key. Security events are
emitted either way.

Why: requirement 4 makes the trail optional, and an app that does not need one should not carry its keys, its storage
or its checkpoint export.

Override: the app turns it on by importing the entry and passing its `AuditSink` to `createAuth`.

### 2. What goes in the trail: test-cap's session records plus the app's activity records

When the audit trail is on, test-cap appends an audit record for each session fact the reports in section 7 need:
sign-in with its assurance level, step-up, sign-out, revocation, impersonation and break-glass. The app adds
activity records itself with `audit.record(session, { action, resource, outcome })`.

The docs state that test-cap sees only what the app records. An action the app performs without calling
`audit.record` is absent from the trail, and no check can find it.

Why: the glossary defines the audit trail as both halves, who signed in and what the app recorded. test-cap can vouch
for the first because it runs the ceremonies; only the app knows its own actions.

Override: the app chooses what to record and how finely.

### 3. Each record is canonical JSON in a numbered stream

Every audit record (`AuditRecord`) holds the system (`APP_SYSTEM_ID`), the tenant, a sequence number `seq`, the key id
of the chain key that linked it, and its content. It is serialised as RFC 8785 canonical JSON (JCS) before anything is
computed over it.

The store writes records with the atomic operation `appendAudit(tenant, stream, seq, record)` ([ADR
0002](0002-store-port-and-atomic-operations.md)). It answers `gap` for a `seq` that leaves a gap and `duplicate` for one
already stored, and stores neither. `store/sql` backs this with a unique `(stream, seq)` constraint, and the conformance
kit runs concurrent appends against it.

Why: canonical JSON gives one byte string per record, so a verifier in another language or another year computes the
same MAC. A sequence the store refuses to break turns a lost or duplicated append into an error at write time rather
than a puzzle at audit time.

Override: none.

### 4. Records are chained with HMAC-SHA-256 under `AUTH_AUDIT_KEY`

Each record's link is HMAC-SHA-256, keyed by `AUTH_AUDIT_KEY`, over the previous link and the record's canonical
bytes. A change to any record breaks every link after it.

The key carries a key id, and the record names the id it was linked with. Rotating the key means adding a new key that
links new records; old keys stay available for verification. The variable's format and its `expiresAt` are
[ADR 0022](0022-environment-variables.md)'s.

Why: a keyed link means an attacker holding only the database cannot write a record that verifies. The key id lets the
key change without rewriting history.

Override: the app supplies and rotates the key.

### 5. Signed checkpoints, exported by the app

Every N records or T minutes, test-cap signs the chain head and its `seq` with Ed25519 under `AUTH_AUDIT_SIGNING_KEY`,
producing a checkpoint. The app's `exportCheckpoint` function sends it to storage independent of the database (another
account, a write-once bucket, a separate service). test-cap never chooses that storage.

Why: a checkpoint outside the database fixes the chain up to that point against anyone who controls the database, even
one who also holds `AUTH_AUDIT_KEY`. The signing key is separate from the chain key so that leaking one does not give
both powers.

Override: the app sets N and T and supplies `exportCheckpoint`.

### 6. Independent verification

`verifyAudit(records, checkpoints, publicKey)` recomputes the chain and checks each checkpoint's signature. It returns
an `AuditVerification` that reports:

| Tampering     | How it shows                                                     |
| ------------- | ---------------------------------------------------------------- |
| Modification  | a record's link no longer matches                                |
| Deletion      | a `seq` is missing, or a link no longer matches                  |
| Reordering    | `seq` order and link order disagree                              |
| Truncation    | the records end before the `seq` of the last exported checkpoint |
| Forged anchor | a checkpoint's signature fails under the public key              |

A result the verifier cannot settle (for example, a record linked with a key id it was not given) is reported as
`indeterminate`, never as a pass.

Why: verification must run where the database owner has no say, so it takes the records, the exported checkpoints and
the public key as plain inputs and reads nothing else.

Override: none. The plan's signature omits the chain keys that recomputing an HMAC link needs; see Open 1.

### 7. Reports

`sessionTimeline` and `accessReport` read the trail and answer who signed in to which system, when, at what assurance
level, and with what impersonation or break-glass. They report only what the trail holds.

Why: these are the questions requirement 4 names.

Override: the app filters by tenant, system, subject and time range.

### 8. Privacy

- Recording the client IP and user agent is opt-in.
- Retention is set per tenant.
- A legal hold stops retention from removing a tenant's records until it is lifted.
- The app's `redact` hook runs on every record before it is serialised, so the chain covers the redacted form and a
  redacted value is never stored.

Why: an audit trail is personal data. Keeping less by default, and letting the app remove what it must not keep before
it becomes part of the chain, avoids a later edit that verification would report as tampering.

Override: each item is the app's or tenant's setting.

### 9. Who may read the trail is access-cap's decision

test-cap provides the read functions and makes no access decision about them. The app, or access-cap, decides who may
call them.

Why: test-cap is authentication only.

## Consequences

- An app gets a tamper-evident record of sign-ins and its own recorded actions, verifiable without trusting the
  database.
- The app has two more secrets to hold, a function to export checkpoints, and somewhere outside its database to keep
  them.
- The docs say these features "map to" HIPAA §164.312(b) (audit controls) and PCI DSS v4 requirement 10 (log and
  monitor access). This is traceability for internal readers (ADR 0017), not a compliance claim.
- A store must implement `appendAudit` with its gap and duplicate guarantee; the conformance kit proves it.

## Limits

- **An attacker holding the store and both keys** can rewrite history back to the last exported checkpoint. That is why
  the signing key and the checkpoints live outside the database.
- **Records after the last checkpoint** can be silently removed by anyone who controls the database: truncation is
  detected only back to the last exported checkpoint. N and T bound that window.
- **test-cap sees only what the app records.** An unrecorded action leaves no trace.
- **An exported checkpoint is only as safe as the storage the app chose.** test-cap cannot check that it is
  independent.
- **Stored records cannot be changed later**, including to erase personal data, without verification reporting a
  modification. The `redact` hook and retention are the only supported ways to keep data out.
- **Security events are not covered.** Their storage and integrity are the app's (ADR 0015).

## Open

1. **`verifyAudit` needs the chain keys.** Recomputing an HMAC link requires `AUTH_AUDIT_KEY` (every key id in use),
   but the plan's signature passes only the Ed25519 public key. With the public key alone, a verifier can check
   checkpoint signatures and `seq` continuity, but not record content. Recommendation: add the chain keys as a fourth
   input, `verifyAudit(records, checkpoints, publicKey, chainKeys)`, and report content as `indeterminate` when they
   are not given.
2. **Defaults for N and T.** The plan names the trigger but not the values. Recommendation: N = 1000 records, T = 15
   minutes, whichever comes first, both configurable; the policy report lists the values.
3. **How T is triggered without a timer.** Serverless and edge-style hosts have no background timer. Recommendation:
   check T on each append and expose `audit.checkpoint()` for the app to call on its own schedule; the core starts no
   timer.
4. **What a stream is.** `appendAudit(stream, seq, record)` names a stream but the plan does not define one.
   Recommendation: one stream per system and tenant, so retention, legal hold and verification are independent per
   tenant.
5. **Retention versus verification.** Removing old records under retention looks like deletion to `verifyAudit`.
   Recommendation: retention removes only a whole prefix ending at an exported checkpoint, and the verifier accepts that
   checkpoint as the stream's new starting anchor, so a retention cut is told apart from a deletion in the middle.
