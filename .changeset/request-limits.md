---
"test-cap": minor
---

Limit requests to every `/auth` route per client, and make every limit changeable or replaceable (ADR 0009 §8).

- **Request limits**: each request is counted per client (an IPv4 address or an IPv6 /64) before its route runs, with
  the store's atomic `increment`, so every instance shares the count. Defaults: 100 per 10 seconds on any route; 10 per
  10 seconds on `sign-in`, `step-up`, `totp/verify`, `totp/enrol`, `totp/confirm`, `email/confirm` and `recovery`;
  20 sign-ups an hour. Over a limit, a request answers `429 rate-limited` with `Retry-After`, before any account is
  created or looked up. On in every mode.
- **The new `rateLimit` option**: `windowMs` and `max` change the default rule; `rules` takes a rule, `false`, a
  rate-limiter-flexible limiter or a function of the request per route id, and refuses to start on an id that is no
  route; `limiter` builds each rule's limiter over the app's own backend; `rateLimit` can
  also be one limiter for every route. `rateLimit: false` turns the limits off in any mode, for an app that limits at
  its gateway.
- **Limits on existing libraries** (ADR 0030): every limit counts with rate-limiter-flexible, and client addresses are
  parsed with ipaddr.js and forwarded-parse, three new dependencies pinned to exact versions. New export:
  `createStoreLimiter`, the library's store limiter over the app's `AuthStore` and the default behind every limit. A
  `Forwarded` value that is not RFC 7239 now names no hop.
- **The guessing throttle**: `throttle` now also takes the app's own `Throttle`, or `false`, which production and
  staging refuse (NIST SP 800-63B-4 requires throttling). The new `failureCeiling` lowers the 100-failure ceiling and
  refuses to raise it.
- **The other limits**: `emailLimit` changes the confirmation-mail send limits (`perAddress`, `perClient`) or replaces
  their counters with rate-limiter-flexible limiters of the app's; `emailCodeAttempts` lowers the 5 attempts an
  emailed code allows, never raising them; `stuffing` now also takes the app's own `StuffingDetector`.
  `emailLimit: false` and `stuffing: false` are refused in production and staging.
- **Refusal events**: a refused request, a throttled guess and an email code past its attempts emit their failure
  event once per client or account per window by default; `refusalEvents: "every"` emits one per refusal.
- **Operator diagnostics**: `onDiagnostic` is told once when a request has no client address (`client-address-missing`)
  and when the app turned a limit off (`rate-limit-off`, `throttle-off`, `email-limit-off`, `stuffing-off`).
