# 0015: Security events

## Status

Accepted (2026-11-15). The event model, the `onEvent` sink, redaction and the events of password and TOTP sign-in and
the session lifecycle are implemented in phase 3; each later phase adds the events of the flows it builds. Answers
[handoff question](../../GLOSSARY.md) 15.

Planned tests:

- `test/events/ocsf-schema.test.ts` (every emitted event validates against the OCSF 1.9.0 class it names)
- `test/events/flow-activity-map.test.ts` (every flow in the table below emits exactly the listed activities)
- `test/events/redaction.test.ts` (fast-check: no secret, code or full token appears in any serialised event)
- `test/events/always-on.test.ts`
- `test/events/separate-from-audit.test.ts`
- `test/attacks/secret-in-security-event.test.ts`

The recommendations under Open are provisional defaults until the owner decides.

## Context

An app needs to know who signed in, who failed, and what changed on an account, in a form its security tooling can
read. The handoff fixed the format: OCSF, at least the Authentication and Account Change classes, using the shared
event types access-cap introduces. It asked which classes and fields each flow uses, how many success events to
expect, and what is redacted.

Two records are easy to confuse. A **security event** is what test-cap always emits about authentication. The **audit
trail** (`test-cap/audit`, [ADR 0020](0020-audit-integrity-model.md)) is an opt-in, tamper-evident record of who signed
in and what the app recorded during the session. Both are defined in `GLOSSARY.md`.

OCSF 1.9.0 facts this decision rests on (schema.ocsf.io, checked 2026-11-15):

- Every event needs `activity_id`, `category_uid`, `class_uid`, `type_uid` (`class_uid * 100 + activity_id`),
  `severity_id`, `time` and `metadata` (product and version). In the IAM classes, `user` needs one of `account`,
  `name` or `uid`.
- Authentication (3002) activities: 1 Logon, 2 Logoff, 3 Authentication Ticket, 4 Service Ticket Request, 5 Service
  Ticket Renew, 6 Preauth, 7 Account Switch (with `account_switch_type_id` 2 Impersonate). It carries `is_mfa`,
  `auth_factors`, `auth_protocol_id` (4 OpenID, 5 SAML), `session`, `actor` and `status_id`.
- Account Change (3001) activities: 1 Create, 2 Enable, 3 Password Change, 4 Password Reset, 5 Disable, 6 Delete,
  7 Attach Policy, 8 Detach Policy, 9 Lock, 10 MFA Factor Enable, 11 MFA Factor Disable, 12 Unlock.
- The 1.9.0 schema marks Account Change "DEPRECATED since v1.9.0" and names User Management (3007) as its
  replacement. See Open 1.

## Decision

### 1. Two OCSF classes: Authentication 3002 and Account Change 3001

Sign-in attempts, session ends and account switches are Authentication events. Changes to an account and its
authenticators are Account Change events. Each event's `status_id` is 1 (Success) or 2 (Failure). Where an OCSF
activity has no exact match, the event uses 99 (Other) with an `activity_name` that says what happened.

Why: these are the two classes the plan names. Using OCSF's own activities where they fit lets an app's security
tooling read the events without a test-cap mapping.

### 2. Which activity for which flow

| Flow                                | Event                                                                         |
| ----------------------------------- | ----------------------------------------------------------------------------- |
| F01 sign-up                         | 3001 Create; 3001 MFA Factor Enable for each authenticator enrolled           |
| F02 password sign-in                | 3002 Logon, success or failure                                                |
| F03 TOTP enrolment                  | 3001 MFA Factor Enable; removal is 3001 MFA Factor Disable                    |
| F04 TOTP verification               | 3002 Logon, success or failure, with `is_mfa` and `auth_factors`              |
| F05 passkey and security-key reg.   | 3001 MFA Factor Enable; removal is 3001 MFA Factor Disable                    |
| F06 passkey authentication          | 3002 Logon, success or failure                                                |
| F07 recovery codes                  | issue: 3001 Other ("recovery codes issued"); redeem: 3001 Other ("recovery")  |
| F08 email address confirmation      | 3001 Other ("email confirmed")                                                |
| F09 account recovery by email       | 3001 Other ("recovery"); a password set during it is 3001 Password Reset      |
| F10 opt-in email sign-in            | 3002 Logon, marked as a deviation                                             |
| F11 OIDC sign-in and linking        | 3002 Logon with `auth_protocol_id` 4; a link is 3001 Other ("linked")         |
| F12 SAML SP sign-in                 | 3002 Logon with `auth_protocol_id` 5                                          |
| F13 step-up                         | 3002 Logon on the existing session, marked as a step-up                       |
| F14 session lifecycle               | issue: the Logon of its flow; sign-out, expiry and remote revoke: 3002 Logoff |
| F15 API keys                        | create and revoke: 3001 Other; a rejected key: 3002 Logon failure             |
| F16 delegations to agents           | issue and revoke: 3001 Other; a rejected delegation: 3002 Logon failure       |
| F17 admin impersonation             | 3002 Account Switch, `account_switch_type_id` 2; its end is 3002 Logoff       |
| F18 break-glass                     | 3002 Logon, flagged as break-glass; its end is 3002 Logoff                    |
| F19 deprovision hook                | 3001 Disable; 3002 Logoff for each session it revokes                         |
| F20 audit                           | none: the audit trail has its own records                                     |
| F21 default pages and client assets | none of their own: the flows they drive emit                                  |
| F22 adapter transport               | none: a request denied by deny by default is not an authentication event      |

A password change outside recovery is 3001 Password Change. A throttled attempt is a 3002 Logon failure whose
`status_detail` says it was throttled; there is no Lock event, because test-cap throttles and never locks out
([ADR 0009](0009-abuse-and-proxy-trust.md)). A request refused by the CSRF check
([ADR 0011](0011-csrf-and-xss-boundary-with-secure-cap.md)) is a failure of the flow it was trying to start.

Why: one table, pinned by a test, means a reviewer can predict the events of any flow, and a new flow cannot ship
without deciding its events.

### 3. Delivered to the app's `onEvent` sink, always

Every event is a `SecurityEvent` and goes to the `onEvent` function, an `EventSink`, that the app passes to
`createAuth`. Events cannot be turned off. test-cap does not store or batch them, and emits every event every time,
with one possible exception: whether successful API-key and delegation use is sampled is Open 3. Storing and
filtering are the app's job.

Why: authentication without a record of failures and account changes is unreviewable. Leaving storage to the app
keeps test-cap free of a log backend, the same way it never opens a database connection.

### 4. Redaction is built in

No event contains a password, a TOTP or recovery code, an email code or magic-link token, a session token, an API
key, a delegation token, a CSRF token or any key material. A session appears only as a prefix of the SHA-256 the
store already holds for it (`session.uid`), enough to correlate events and never enough to use.

Why: events leave test-cap for log pipelines that are read by many people and kept for a long time. A secret in a log
is a secret disclosed.

Override: none. The plan states this as a rule, not a default.

### 5. Separate from the audit trail

Events are emitted whether or not `test-cap/audit` is installed, and no event is written to the audit chain.
Turning the audit trail on changes nothing about events.

Why: events serve detection and must be cheap and always present; the audit trail serves after-the-fact proof and is
opt-in. Mixing them would make the cheap stream depend on the expensive one.

### 6. Shaped so access-cap can lift the shared types

The event types live in one module that depends on nothing else in test-cap. Field names are OCSF's own. Everything
OCSF has no field for (subject kind, session assurance level, deviation, step-up, break-glass, reason, tenant) goes
under OCSF's `unmapped` object, in one `test_cap` key. For impersonation, the administrator is OCSF's `actor` and the
target is `user`.

Why: the handoff says access-cap introduces the shared OCSF types. Keeping test-cap's types pure OCSF plus one
namespaced extension lets them move into a shared module without changing a field.

## Consequences

- Volume: one event per sign-in attempt, per step-up, per session end and per account change. The volume from API
  keys and delegations, which are presented on every request, depends on Open 3.
- An app's SIEM can read the events as OCSF without custom parsing; test-cap's extras sit in one known place.
- Changing an event's activity is a visible change to a pinned table, not a quiet code edit.

## Limits

- test-cap emits; it does not deliver reliably. If the app's sink drops an event, test-cap does not retry.
- A deprecated class at the pinned version (Account Change, see Open 1) may be dropped by a later OCSF release.
- The client address and user agent in events follow Open 2; the plan sets an opt-in only for the audit trail.
- Events record what test-cap saw. They say nothing about what the app did after `auth.require` answered `allow`.

## Open

1. **Account Change is deprecated in OCSF 1.9.0.** The plan names 3001; the 1.9.0 schema deprecates it in favour of
   User Management (3007, activities including 1 Create, 8 Password Change, 9 Password Reset, 12 Enable MFA Factors,
   13 Disable MFA Factors, 18 Add Programmatic Credentials, 19 Remove Programmatic Credentials). Recommendation: emit
   3007 for account changes, since it is the current class at the pinned version and has exact activities for API
   keys; keep the table above with 3007's ids. The owner decides, because the plan names 3001.
2. **Client address and user agent in events.** The plan makes recording them opt-in for the audit trail but says
   nothing for events. Recommendation: the same opt-in, so one privacy setting governs both; throttling uses counters
   in the store ([ADR 0009](0009-abuse-and-proxy-trust.md)) and does not depend on events.
3. **Success events for API keys and delegations.** The plan says events are always on but not whether every
   successful API request is a Logon. Recommendation: emit failures always and successful use at most once per key or
   delegation per hour, stated in the docs as the one sampling test-cap does.
4. **Session hash prefix length.** Recommendation: the first 16 hex characters (64 bits) of the stored SHA-256.
5. **A sink that throws.** Recommendation: the authentication outcome stands, and the error is reported through
   test-cap's error model; an event sink never decides whether someone signs in.
