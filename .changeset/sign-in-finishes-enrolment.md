---
"test-cap": minor
---

A password sign-in to an account with no confirmed second factor answers `enroll`, with a `pre-auth` session. The default
sign-in page then goes on to TOTP enrolment. Before, such an account signed in at AAL1 and could neither reach a page nor
enrol TOTP, so it was stuck for good. A policy that lets a password alone meet the default requirement signs in as
before.

That session cannot replace the password: `POST /auth/password` answers `409 password-set`. A password changes only
through recovery, which signs the account's other sessions out.

Finishing enrolment now revokes the account's other sessions. A `pre-auth` session whose account already has a confirmed
second factor is signed out. So someone who knew only the password while enrolment was unfinished cannot add a TOTP of
their own later. Until a second factor is confirmed, the password is the only factor, so whoever holds it can finish
enrolment too.
