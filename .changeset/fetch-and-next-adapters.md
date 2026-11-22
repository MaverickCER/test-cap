---
"test-cap": minor
---

Add two entries. `test-cap/fetch` has `withAuth`, which wraps a handler that takes a Web `Request`: it serves
`/auth/*` and protects every other route by default. Its handler has the shape `Bun.serve` and `Deno.serve` take; the
tests run it on Node. `fetchAuth` serves the `/auth/*` routes alone.

`test-cap/next` adds the Next.js 16 App Router surfaces, tested on Next.js 16.4.6:

- `nextAuthHandler` for `app/auth/[...path]/route.ts`;
- `nextServerAuth`, the authoritative check for route handlers, server functions and the data-access layer;
- `nextProxy`, an optional proxy for early redirects that is not protection.
