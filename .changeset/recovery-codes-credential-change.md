---
"test-cap": minor
---

Making a new set of recovery codes is a credential change (ADR 0006 §7). It rotates the session that made it and
revokes the account's other sessions, and the reply sets the new session cookie and the next CSRF token. A request
that loses a race to another new set gets `401 unauthenticated`, and every session of the account is revoked.
