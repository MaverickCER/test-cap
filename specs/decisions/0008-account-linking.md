# 0008: Account linking needs proof of the existing account, never a matching email

## Status

Accepted (2026-11-15). Implemented in phase 5 (OIDC sign-in and linking, flow F11) and phase 8 (the same rules for
SAML, flow F12).

Answers [handoff question](../../GLOSSARY.md) 8 (account linking).

Planned tests:

- `test/linking/identity-key.test.ts` (a federated identity is found by issuer and subject; changing the email claim
  changes nothing);
- `test/linking/explicit-link-needs-session.test.ts` (linking happens only from a signed-in session that meets the
  default requirement);
- `test/linking/link-is-unique.test.ts` (one issuer and subject links to one account per tenant, also under
  concurrency);
- `test/linking/link-revokes-other-sessions.test.ts`;
- `test/attacks/oidc-auto-link-to-unverified-account.test.ts` (an OIDC sign-in whose email matches an account is never
  linked to it, whether `email_verified` is false, missing or true);
- `test/attacks/oidc-email-verified-string.test.ts` (`email_verified` from an issuer outside the trust config counts as
  unverified);
- `test/attacks/pre-account-hijack.test.ts` (an unconfirmed sign-up never claims an address, and cannot be taken over
  by its real owner's later sign-up);
- `test/attacks/federated-identity-collision.test.ts` (a subject from one issuer can never sign in to an account
  linked to another issuer's subject).

The recommendations under Open are provisional defaults until the owner decides.

## Context

An OIDC sign-in whose email matches an existing account is a known takeover path (question 8). Better Auth's
advisories show three forms of it:

- an OAuth identity auto-linked to an account pre-registered with an unverified email (`g38m-r43w-p2q7`);
- a provider's unverified email treated as verified (`9hm7-xhfp-cx58`);
- a pre-account hijack through a magic link or email OTP (`qq9h-g4jm-xgf3`).

Several of its SSO advisories (`prpr-5gj3-qqhg`, `mx9r-x6ww-qjw9`, `8c5h-wx78-2cfg`) are the same mistake from
another side: trusting a claim about who someone is from a party that was never in a position to prove it.

In a pre-account hijack, the attacker signs up first with the victim's address and a password of their own, and never
confirms it. When the victim later arrives, often through OIDC, a careless system merges the two, and the attacker's
password still opens the merged account.

## Decision

### 1. A federated identity is its issuer and subject

An OIDC identity is the pair of issuer and `sub`; a SAML identity is the identity provider and its persistent
`NameID`. The pair is the only key a federated sign-in is matched on. It is stored with `createUnique` (ADR 0002), so
one pair links to at most one account in a tenant. The email claim is profile data and never a key.

Why: `sub` is stable and issued by the party that authenticated the person; an email claim is neither.

### 2. Linking needs proof of the existing account

An identity is linked to an existing account only from a session signed in to that account that meets the default
requirement (AAL2), as an explicit action the person takes (flow F11). Linking is a credential change: it revokes the
account's other sessions and emits an Account Change event (ADR 0006, ADR 0015).

Why: proof of the existing account is the only evidence that the person linking is its owner. The OIDC evidence alone
is AAL1 unless the issuer is in the trust config (ADR 0005), so it could not authorise a link to an AAL2 account even
if it were trusted to identify one.

### 3. test-cap never auto-links on an unverified email

An `email_verified` claim that is false or missing never links an identity to an account. An `email_verified` claim
from an issuer outside the trust config counts as unverified.

Why: these are the two advisories above, stated as rules. An unverified claim is the identity provider repeating what
the user typed.

### 4. An unconfirmed sign-up claims nothing

Sign-up confirms the email address before the account holds it (flows F01 and F08). The identifier is claimed with
`createUnique` only when its confirmation code is redeemed. An unconfirmed sign-up expires and never blocks, merges
with or receives the address's real owner.

Why: the pre-account hijack needs an account that holds an address its creator never proved. Claiming the address
only on confirmation removes that account.

## Consequences

- A federated sign-in either finds the account linked to its issuer and subject or starts a new sign-up; it never
  finds an account by email.
- A person who already has an account and signs in with OIDC for the first time must sign in the old way once and link
  from there.
- The rules apply to SAML unchanged when it arrives, and to every issuer a tenant configures (ADR 0012).

## Limits

- **Verified-email auto-linking is not settled by the plan.** The plan forbids auto-linking on an unverified email; it
  does not say whether a verified email from a trusted issuer may auto-link. See Open.
- **What a person sees when the email matches an existing account** is not settled, and it touches enumeration (ADR
  0009). See Open.
- **Issuer trust is configuration.** An issuer in the trust config that lies about `email_verified` or reassigns a
  `sub` is outside what test-cap can detect. The issuer allowlist and the block on private and link-local discovery
  addresses (ADR 0026) bound which issuers can be configured, not what they assert.
- **Email address changes** are part of flow F08, not this record; an address change that leaves old codes valid
  (`hwq2-v29r-p69r`) is an attack catalogue entry for that flow.

## Open

1. **Auto-linking on a verified email from a trusted issuer.** Recommendation: never. Section 2's explicit link is
   always available, and it removes the class entirely instead of narrowing it to "trusted issuers that never err".
2. **An OIDC sign-in whose verified email matches an existing account.** Recommendation: do not create a second
   account with the same address; show the same page as any new federated sign-up, which tells the person to sign in
   with their existing method and link from their account if they already have one. The reply is identical whether or
   not an account exists, so it reveals nothing (ADR 0009).
3. **Unlinking.** Recommendation: unlinking is a credential change at the default requirement, and is refused when it
   would leave the account unable to meet the default requirement with the authenticators that remain.
