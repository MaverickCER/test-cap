---
"test-cap": patch
---

Revoke every session of the account when a TOTP confirmation fails partway. This covers a signed-in account that
confirms a new TOTP authenticator, when the session rotation that follows fails or finds its session gone. Before, the
new authenticator stayed and the account's other sessions kept working behind the error reply.
