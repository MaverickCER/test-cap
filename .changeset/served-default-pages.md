---
"test-cap": minor
---

`auth.handle` now serves the default pages (ADR 0025 §4). They answer `GET` on `/auth/sign-up`, `/auth/email/confirm`,
`/auth/password`, `/auth/totp/enrol`, `/auth/sign-in`, `/auth/step-up` and `/auth/sign-out`, under the strict CSP with
no inline script and `no-store`. Their script and stylesheet are served at `/auth/assets/test-cap.<hash>.<js|css>`,
cached as immutable.

A form post with `Accept: text/html` answers with a 303 to the next step, or the page again with the refusal. A JSON
post keeps its JSON. A method other than `GET` or `POST` on a page's path now names both in `Allow`. The form model
gains the `email-confirm` form, its messages, and the `too-common` and `breached` outcomes.

The origin check now treats `Origin: null` as an absent `Origin`, so only `Sec-Fetch-Site: same-origin` passes it
(ADR 0011 §2). A browser sends `Origin: null` for a form post from a `no-referrer` page, such as the default pages.
