---
"test-cap": minor
---

Add `createAuth` and the first complete slice behind it. The dispatcher serves sign-up, password sign-in, TOTP
enrolment and verification, step-up, sign-out, the session list and remote revoke. Every `POST` route checks CSRF, and
every reply carries the security headers. Sign-up and sign-in answer a known and an unknown account the same way.

Add `defineAuthPolicy` and the policy types to the main entry. Add the `test-cap/express` entry: its `expressAuth`
serves `/auth/*` and protects every other route by default.
