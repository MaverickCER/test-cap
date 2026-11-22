---
"test-cap": minor
---

Bound what a signed-in session can grow. A session keeps only the newest evidence of each (method, authenticator) and
the newest step-up of each method (ADR 0005 §2). An account holds at most 5 TOTP authenticators: a sixth enrolment
answers `409 too-many-authenticators`. Beginning an enrolment replaces any other still waiting for its code
(ADR 0027 §6).
