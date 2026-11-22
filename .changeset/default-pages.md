---
"test-cap": minor
---

Add the form model and the default page types (ADR 0025). `FormModel`, `FieldState` and `Messages` cover sign-in,
sign-up, choosing a password, the second-factor challenge, TOTP enrolment and step-up. `PageContext` and `PageAssets`
are what the default pages take. The pages render on the server, work without JavaScript, and load no inline script
or style. Each form posts the fields its `/auth/*` route declares, with the synchronizer token as `csrfToken`.
`PageContext.hidden` carries what a route needs from the step before: `authenticatorId` on TOTP enrolment,
`challenge` on step-up. Sign-up follows the API's steps, each on its own page.
