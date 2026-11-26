---
"test-cap": minor
---

Harden sign-in against guessing, stuffing and lost authenticators (phase 4).

- **Throttling** (ADR 0009): passwords, TOTP codes and recovery codes are counted per identifier, per identifier and
  client, and per client (an IPv4 address or an IPv6 /64). After 5 free failures in 15 minutes each failure doubles a
  wait from 1 second to 15 minutes; a blocked attempt answers `429 rate-limited` with `Retry-After`. Failures never lock
  an account. New `createAuth` options: `throttle` (`ThrottleConfig`).
- **Failure ceiling**: an authenticator stops after 100 failures in a row; the account's others keep working.
- **Credential stuffing**: a client failing against 20 identifiers in 15 minutes is flagged. New options: `stuffing`
  (`StuffingConfig`) and `challengeHook` (`ChallengeHook`); with a hook, a flagged client's sign-in answers
  `403 challenge-required` until the hook passes it.
- **Proxy trust** (ADR 0009 §5): `trustedProxies` is now read, and takes IP addresses, CIDR ranges or a platform
  preset from the new `platform()` (`aws-alb`, `cloudfront`, `cloudflare`, `vercel`, `fly`, `netlify`, `nginx`), each
  naming the one header it reads. Presets are tested in simulation through every adapter, not on the platforms. The new
  `forwardedHeader` option names the header the app's own proxies set, `x-forwarded-for` or `forwarded` (RFC 7239).
- **Gateways** (ADR 0024 §6): `publicBasePath` puts a stripped prefix back on every link, redirect and email URL. The
  Next.js and TanStack Start route handlers take a `clientAddress` option.
- **Operator diagnostics**: the new `onDiagnostic` hook is told once when a forwarding header arrives from an
  undeclared proxy, or when a state-changing request carries neither `Origin` nor `Sec-Fetch-Site`.
- **Recovery codes** (ADR 0007): `POST /auth/recovery-codes`, `POST /auth/recovery` and `POST /auth/recovery/finish`.
  A redeemed code gives a recovery-only session with no level, signs out the account's other sessions and emails its
  address.
- **Fresh proof for credential changes** (ADR 0005 §8): enrolling TOTP and making recovery codes need a multi-factor
  ceremony in the last 15 minutes.
- **Deprovisioning**: `auth.admin.deprovision(subject)` disables the account and ends its sessions; a disabled
  account's session is refused on its next request.
