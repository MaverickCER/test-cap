---
"test-cap": minor
---

Add email address confirmation at sign-up (F08, ADR 0021). `sendEmail` is now required.

Sign-up mails the address a 6-digit code from the `RandomSource`, valid for 24 hours. The store keeps only an HMAC of
the code, under a key HKDF derives from `AUTH_ENCRYPTION_KEY`. `POST /auth/email/confirm` redeems the code once and
claims the normalised address with `createUnique`. When another account confirmed the address first, the reply is the
same and nothing is claimed. `POST /auth/email/resend` mails a new code.

Sends are limited per address (1 a minute, 5 an hour) and per IP address or IPv6 /64 (20 an hour). Five wrong tries
end a code for the rest of its life, even when the store fails the write that kills it. The pre-auth flow is now
sign-up, confirmation, password, TOTP, so an account signs in again later by its confirmed address. A confirmation
emits an OCSF User Management Update and adds no assurance.

Also: federated evidence now counts its multi-factor time from `min(authTime, at)`. Production and staging refuse the
keys the examples commit. A malformed TOTP `authenticatorId` is now `400 malformed-body`, refused before the store
sees it.
