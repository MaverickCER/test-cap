# 0011: CSRF and XSS boundary with secure-cap

## Status

Accepted (2026-11-15). Implemented in phase 3 (default sign-in pages, response headers and caching) and phase 4
(CSRF). Answers [handoff question](../../GLOSSARY.md) 11.

Planned tests:

- `test/attacks/csrf-state-changing-route.test.ts`
- `test/attacks/login-csrf.test.ts`
- `test/attacks/reflected-xss-error-page.test.ts`
- `test/security/response-headers.test.ts`
- `test/security/cache-control.test.ts`
- `test/e2e/default-pages-csp.spec.ts` (Playwright, three engines: no CSP violation on any default page)

The recommendations under Open are provisional defaults until the owner decides.

## Context

secure-cap is a planned package for XSS, CSRF and injection in an app as a whole. It does not exist yet, and its
runtime part will stay private. test-cap cannot wait for it: a sign-in form that accepts a cross-site POST lets an
attacker sign a victim in to the attacker's account (login CSRF), and a default page that reflects input unescaped
hands an attacker the session.

The handoff asked where the line between the two packages runs. The plan answers by ownership of the surface.
test-cap serves its own routes and pages through the **dispatcher** (`auth.handle`, see `GLOSSARY.md`): every
`/auth/*` route, the **default pages** and their hashed assets. Everything else belongs to the app.

## Decision

### 1. test-cap protects every route and page it serves

Each defence below applies to every response the dispatcher produces, with no list of exemptions. The app's own
routes get none of these headers or checks from test-cap; that surface is secure-cap's.

Why: test-cap is the only party that knows which of its routes change state and what its pages render. Leaving any
of them to a package that does not exist yet would leave them unprotected.

### 2. CSRF: origin check plus synchronizer token on every state-changing route

Every state-changing request to a test-cap route passes two checks:

- **Origin.** The `Origin` header must equal `APP_ORIGIN`. When `Origin` is absent or `null`, `Sec-Fetch-Site` must
  be `same-origin`. A request carrying neither is rejected. `null` is what a browser sends for a form post from a page
  whose referrer policy is `no-referrer`, as the default pages' is (Open 2); found by the phase-7 browser tests.
- **Synchronizer token.** The request carries a token derived under `AUTH_CSRF_KEY` and bound to the browser state it
  was issued to. The default pages put it in a hidden field; `test-cap/client` sends it with its requests.

Sign-in and sign-up count as state-changing, so login CSRF is covered before any session exists. OIDC and SAML
callbacks, which arrive cross-site by design, are protected instead by the **federation transaction**: state, nonce,
PKCE S256 and `InResponseTo`, bound to the single-use `__Host-test-cap-tx` cookie
([ADR 0006](0006-sessions-and-cookies.md)).

Why: the origin check stops a cross-site request on modern browsers; the token covers a browser or proxy that drops
the headers. Two independent checks mean one bypass is not enough.

Override: none in the plan. Any later relaxation would be a deviation listed in the policy report
([ADR 0026](0026-strict-defaults-and-deployment-mode.md)).

### 3. XSS: one escaping renderer and a strict CSP

- The default pages are produced by one HTML renderer that escapes every interpolated value for its context. No
  other code path writes HTML.
- Every message the app replaces through `messages` is rendered as text.
- Pages carry a strict Content-Security-Policy: no inline script, scripts and styles only from the hashed assets
  test-cap serves, and `frame-ancestors 'none'`.
- Every response carries `X-Content-Type-Options: nosniff`.

Why: a single renderer is one place to get escaping right and one place to test it. The CSP is the second line: an
escaping bug that slips through cannot run injected script. `frame-ancestors 'none'` stops clickjacking of the sign-in
and consent pages.

Override: none in the plan.

### 4. Caching is split

Auth responses (every `/auth/*` route and every default page) carry `Cache-Control: no-store`. Hashed assets carry an
immutable, long-lived `Cache-Control`, which is safe because their name changes whenever their content does.

Why: a cached auth response can leak a token, a CSRF value or a signed-in page to the next user of a shared cache.
Hashed assets carry no user data, and caching them keeps the pages fast.

### 5. secure-cap keeps the app's other routes

CSRF, XSS and injection on routes and pages the app serves itself are outside test-cap. Deny by default
([ADR 0024](0024-adapters-and-deny-by-default.md)) decides whether a request to an app route is authenticated; it does
not check that the request was intended.

## Consequences

- An app gets CSRF, XSS and caching protection on its whole authentication surface by mounting the adapter, with no
  configuration.
- The React components ([ADR 0025](0025-default-ui-and-form-contract.md)) run inside the app's own pages, under the
  app's CSP. They render through React, which escapes text, and post to test-cap routes, which apply section 2.
- When secure-cap ships, the boundary does not move: test-cap keeps its own surface, so the two packages never apply
  conflicting headers to one response.

## Limits

- Until secure-cap exists, the app's own state-changing routes rely on the session cookie's `SameSite=Lax` alone.
  That stops a cross-site POST, but not a request from a sibling subdomain (same-site) or a state change made with a
  GET.
- The CSP protects the default pages only. An app page that embeds test-cap's components is as safe as that page's
  CSP.
- A client that sends neither `Origin` nor `Sec-Fetch-Site` on a state-changing request is refused, so very old
  browsers and hand-made HTTP clients cannot use the default forms.

## Open

1. **CSRF token construction.** The plan names `AUTH_CSRF_KEY` and a synchronizer token, not the binding.
   Recommendation: HMAC-SHA-256 under `AUTH_CSRF_KEY` over the session's stored hash (or, before sign-in, a random
   pre-session value in a `__Host-` cookie), a purpose label and an expiry, tagged with the key id so the key can
   rotate; compared in constant time.
2. **The exact CSP and companion headers.** Recommendation: the directives `default-src 'none'`,
   `script-src 'self'`, `style-src 'self'`, `img-src 'self'`, `connect-src 'self'`, `form-action 'self'`,
   `base-uri 'none'` and `frame-ancestors 'none'`, plus `Referrer-Policy: no-referrer` so a magic-link token in a URL
   never leaks through `Referer`. Check `form-action` against federation: Chromium applies it to redirects after a
   form submit, so a form that posts to an OIDC start route which redirects to the IdP needs either a plain link or
   the IdP origin in `form-action`.
3. **A stopgap for app routes before secure-cap.** Recommendation: expose test-cap's origin check and token check as
   a helper an app can call on its own state-changing routes, documented as temporary until secure-cap ships.
