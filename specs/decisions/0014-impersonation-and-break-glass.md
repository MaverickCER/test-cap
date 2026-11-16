# 0014: Impersonation and break-glass

## Status

Accepted (2026-11-15). Implemented in phase 8, with the other admin calls. Answers handoff question 14.

Planned tests:

- `test/admin/impersonation-requires-fresh-aal2.test.ts`
- `test/admin/impersonation-requires-reason-and-limit.test.ts`
- `test/admin/impersonation-blocks-credential-changes.test.ts`
- `test/admin/break-glass-time-limit.test.ts`
- `test/events/impersonation-and-break-glass-flags.test.ts`
- `test/report/break-glass-review.test.ts`
- `test/attacks/impersonation-session-fixation.test.ts`

## Context

Support staff sometimes need to see an app as a particular user sees it, and operators sometimes need access when
the normal path is broken, for example when a tenant's IdP is down. Both are legitimate and both are dangerous: an
administrator acting as someone else can do anything that person can, and emergency access by definition skips the
normal requirements.

The two are defined in `GLOSSARY.md`. An **impersonator** is an administrator acting as another user, recorded on the
subject and on every event while it lasts. **Break-glass** is emergency access by an administrator, outside the
normal requirements, with a reason and a time limit, flagged on every event and listed for review.

The handoff asked whether to support impersonation, how it is marked, which actions are blocked and what events it
produces. The plan supports both, under one set of guards.

## Decision

### 1. Starting either needs a fresh AAL2+ administrator session

The impersonate and break-glass admin calls (flows F17 and F18) start only from an administrator's own session that
holds AAL2 or above from recent evidence. A session whose last multi-factor ceremony is not recent enough gets `step-up`
first. Whether a given administrator may call them is the app's or access-cap's decision; test-cap checks the assurance.

Why: these calls hand out another person's access or bypass requirements. They need proof that the administrator is
present now, not that they signed in this morning.

### 2. A reason and a time limit, always

Each call requires a non-empty reason and a time limit. When the limit passes, the impersonation or break-glass session
ends. The session token rotates when it starts ([ADR 0006](0006-sessions-and-cookies.md)).

Why: the reason is what a reviewer reads later; the time limit bounds the damage of a forgotten or stolen session.
Rotating the token stops a token from before the switch from carrying the new powers.

Override: the administrator sets the reason and the limit within the policy's maximum.

### 3. Flagged on every event

While an impersonation or break-glass session lasts, every security event it causes names the administrator, the target
user (for impersonation), the reason and the flag ([ADR 0015](0015-security-events.md)). Starting impersonation is an
OCSF Authentication event with activity 7 Account Switch and `account_switch_type_id` 2 (Impersonate). The subject
carries the impersonator, so `auth.require` callers and access-cap see it too.

Why: an action taken by an administrator in someone else's name must never be indistinguishable from the person's
own.

### 4. Credential changes are blocked

An impersonation or break-glass session cannot change any credential of the account it acts in: password, TOTP,
passkeys and security keys, recovery codes, email address, API keys and delegations. The attempt is refused and
emitted as a failed event.

Why: a credential change is how temporary access becomes permanent. Blocking it keeps the account's owner in control,
and removes the obvious way for a malicious administrator to keep access after the time limit.

### 5. The administrator's assurance, never the target's

An impersonation session's `SessionAssurance` comes from the administrator's own evidence. It never inherits the
target user's evidence, and it never exceeds what the administrator proved.

Why: the same rule as delegations ([ADR 0013](0013-human-machine-and-delegation-separation.md)). Assurance describes the
person present, and the person present is the administrator.

### 6. Break-glass is listed for review

The policy report states how break-glass is configured. When `test-cap/audit` is on, `accessReport` and
`sessionTimeline` list every break-glass session with its administrator, reason, time limit and what the app recorded
during it ([ADR 0020](0020-audit-integrity-model.md)).

Why: emergency access is only acceptable when someone looks at each use afterwards.

## Consequences

- Support staff can see what a user sees without learning or resetting that user's password.
- A reviewer can find every impersonation and break-glass session, from the events alone or, with the audit trail,
  from the reports.
- An administrator who needs to fix a user's credentials does it through recovery ([ADR 0007](0007-recovery.md)), not by
  impersonating.

## Limits

- test-cap marks and limits these sessions. It does not decide who is an administrator; that is the app's or
  access-cap's.
- Without `test-cap/audit`, the review list is only as complete as the app's storage of security events.
- An administrator acting within the time limit can do anything the target user can, other than change credentials.
  test-cap records it; it cannot judge whether it was appropriate.

## Open

1. **"Fresh" in numbers.** Recommendation: the administrator's last multi-factor ceremony at most 5 minutes old.
2. **Maximum time limits.** Recommendation: impersonation at most 30 minutes, break-glass at most 60 minutes, each
   shown in the policy report.
3. **What break-glass bypasses.** The plan says "outside the normal requirements" without naming which ones.
   Recommendation: break-glass bypasses only a tenant's enforced SSO and its IdP (the outage case); it never bypasses
   the administrator's own AAL2, and requirements an app marks as never reachable by break-glass stay closed.
4. **Notice to the user.** Recommendation: the impersonated user's session list (`<Sessions/>`) shows past
   impersonation sessions with the administrator and reason.
