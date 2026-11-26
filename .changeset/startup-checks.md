---
"test-cap": minor
---

`createAuth` names more problems in its `ConfigError`, instead of failing on the first request that uses the option:

- a missing `hibpFetch` or `sendEmail`, or an `onDiagnostic` that is not a function;
- an `env` that is not an object, an empty `tenant`, or a `policy` not made by `defineAuthPolicy`;
- a `trustedProxies` that is neither a list nor a preset, and `forwardedHeader` without the proxies that set it;
- `throttle` or `stuffing` given `true`, `null` or a number, and unknown `rateLimit` keys;
- a throttle or stuffing window or delay longer than a year.
