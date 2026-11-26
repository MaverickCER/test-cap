---
"test-cap": minor
---

The throttle keeps an account's keys per kind of secret: a password, a TOTP code and a recovery code. Each has its own
budget, and a success clears only its own. Before, a correct password cleared the failures of TOTP guesses. Whoever held
the password could then guess TOTP codes without waiting. `ThrottleSubject` gains `secret`, which an app's own
`Throttle` receives.

A sign-in the throttle refuses now counts toward the credential-stuffing detector. The client throttle otherwise kept a
spray below the detector's 20 identifiers.

A slot counter that fails with anything but the library's own refusal now refuses the attempt. A string or plain-object
rejection used to let it through.
