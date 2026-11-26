---
"test-cap": minor
---

The limits keep no email address or client address in the app's store. Each counter, and the key of each
`rate-limit-block` record, is now named by an HMAC of its key under a key derived from `AUTH_ENCRYPTION_KEY`
(ADR 0032). Rotating that key starts every count again. A limiter the app passes in still gets the plain key.
