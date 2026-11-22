# 0025: Default UI and form contract

## Status

Accepted (2026-11-15). Implemented in phase 3 (the default sign-in pages of the first slice) and phase 7 (the client,
the form model, the React components, the rest of the default pages, and the browser and accessibility tests). Flow:
F21 (default pages and client assets). Pinned by the UX contract table in section 5 and by:

- `test/pages/progressive-enhancement.test.ts`
- `test/e2e/default-pages-csp.spec.ts`
- `test/pages/hashed-assets.test.ts`
- `test/attacks/reflected-xss-error-page.test.ts`
- `test/forms/model.test.ts`
- `test/react/components.test.tsx`
- `test/client/conditional-mediation.test.ts`
- `test/browser/flows.spec.ts`
- `test/a11y/axe.test.tsx`
- `test/a11y/pa11y.test.ts`

The recommendations under Open are provisional defaults until the owner decides.

## Context

Owner requirement 11: a client, default pages and components. One import gives a whole sign-in, sign-up or recovery
form. The forms are unstyled and accessible, a field's error replaces its help text, global errors sit in the row
above the submit button, and the forms should be pleasant to use.

Sign-in forms are also where many attacks start: reflected input on an error page, a form framed by another site, a
reply that reveals whether an account exists. The UI has to be safe by construction as well as usable.

## Decision

### 1. One form model under every form

`test-cap/forms` is a framework-free description of each form, a `FormModel` with one `FieldState` per field and its
`Messages`: its fields, validation, help and error text, submit
state and focus target. The React components and the default pages are both built on it, so they keep the same UX
contract.

Why: two implementations of one form drift. A single model means the contract is tested once and holds in both.

Override: an app builds its own UI on the form model, or on the core's routes directly.

### 2. The client

`test-cap/client` (`createAuthClient`) wraps `@simplewebauthn/browser` and the core's routes, including
conditional-mediation autofill for passkeys (F06).

Why: the browser half of a passkey ceremony is protocol work and comes from the established library (owner
requirement 1).

### 3. React components

`test-cap/react` exports `<SignInForm/>`, `<SignUpForm/>`, `<RecoverForm/>`, `<MfaChallenge/>`, `<PasskeyEnroll/>`,
`<TotpEnroll/>`, `<RecoveryCodes/>`, `<Sessions/>` and `<StepUp/>`. Each is one import that renders the whole form.

Why: requirement 11 names one import per form.

Override: every string through `messages`, and styling through the `data-test-cap` hooks.

### 4. Default pages

The dispatcher serves server-rendered sign-in, sign-up, recovery and account pages, built on the form model:

- **Progressive enhancement.** Password and email flows work without JavaScript; passkeys need it.
- **Strict CSP and no inline script.** Scripts and the optional stylesheet load from hashed asset URLs.
  [ADR 0011](0011-csrf-and-xss-boundary-with-secure-cap.md) owns the header.
- **Hashed assets.** Asset names carry a content hash and are served immutable; auth responses are `no-store`
  ([ADR 0026](0026-strict-defaults-and-deployment-mode.md)).
- **One escaping renderer** writes every page (ADR 0011).
- **Sign-up follows the API's steps.** The sign-up page posts the identifier alone to `/auth/sign-up`, the next page
  posts the new password to `/auth/password`, then the TOTP enrolment page confirms the app. Each page's form posts
  exactly the fields its route declares; `test/pages/dispatcher-contract.test.ts` submits each one to its route.

Why: an app gets working pages with no UI code, and the pages carry the same protections as the rest of the core.

Override: the app replaces any page with its own UI.

### 5. The UX contract

Each point is tested. Unit tests use Testing Library; the browser tests run on Playwright.

| #   | Promise                                                                                                                      | Test                                              |
| --- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| 1   | Elements are unstyled and carry `data-test-cap` hooks.                                                                       | `test/ux/unstyled-hooks.test.tsx`                 |
| 2   | Every field has a label, and help text linked by `aria-describedby`.                                                         | `test/ux/labels-and-help.test.tsx`                |
| 3   | A field error replaces its help text and sets `aria-invalid`; the help text returns once it is fixed.                        | `test/ux/field-error-replaces-help.test.tsx`      |
| 4   | Global errors go in a `role="alert"` row directly above the submit button.                                                   | `test/ux/global-error-row.test.tsx`               |
| 5   | A failed submit moves focus to the first invalid field, or to the error row.                                                 | `test/ux/focus-after-submit.test.tsx`             |
| 6   | `autocomplete` is correct (`username webauthn`, `current-password`, `new-password`, `one-time-code`), and so is `inputmode`. | `test/ux/autocomplete.test.tsx`                   |
| 7   | An OTP is one input, never split boxes.                                                                                      | `test/ux/single-otp-input.test.tsx`               |
| 8   | Passwords have a show-password toggle, and paste is always allowed.                                                          | `test/ux/password-toggle-and-paste.test.tsx`      |
| 9   | The identifier comes first, and a passkey comes first when one exists.                                                       | `test/ux/identifier-and-passkey-first.test.tsx`   |
| 10  | Values are kept after an error, and fields validate on blur.                                                                 | `test/ux/values-kept-and-blur.test.tsx`           |
| 11  | `aria-busy` is set while submitting, and a double submit is blocked.                                                         | `test/ux/busy-and-double-submit.test.tsx`         |
| 12  | A wait time shows when rate-limited, and resend has a countdown.                                                             | `test/ux/rate-limit-and-resend.test.tsx`          |
| 13  | Messages never reveal whether an account exists.                                                                             | `test/attacks/user-enumeration-responses.test.ts` |
| 14  | Every string is replaceable through `messages`.                                                                              | `test/ux/messages.test.tsx`                       |
| 15  | Animation respects `prefers-reduced-motion`.                                                                                 | `test/browser/reduced-motion.spec.ts`             |
| 16  | Targets meet WCAG 2.2 sizes with the optional stylesheet.                                                                    | `test/browser/target-size.spec.ts`                |
| 17  | Every flow is usable by keyboard alone.                                                                                      | `test/browser/keyboard-only.spec.ts`              |

The glossary points to `specs/architecture.md` for this list; this table is the one owned copy, and architecture.md
links here.

Why: each promise is a behaviour a person notices when it fails. Testing every one keeps "pleasant to use" from being
a matter of taste.

Override: strings, styling and whole pages. The behaviours themselves are fixed in the provided forms.

### 6. Browser and accessibility checks

- **Testing Library and axe** on every component and page, with no violations allowed.
- **Playwright on Chromium, Firefox and WebKit**: password plus TOTP, recovery, step-up and keyboard-only runs, and
  passkeys through a virtual authenticator. The check that a field error replaces its help text, and that global
  errors sit above submit, runs here too.
- **pa11y** against the default pages at WCAG 2.2 AA.

Why: unit tests prove the markup; only a real browser proves focus, autofill and keyboard order.

## Consequences

- An app gets accessible sign-in, sign-up, recovery and account UI with no UI code, or one component import per form.
- Every UI change runs three browser engines, axe and pa11y, which costs CI time (ADR 0018).
- `test-cap/react` adds React as a peer dependency of that entry only.

## Limits

- **Automated accessibility tools find a subset of WCAG 2.2 AA failures.** Passing axe and pa11y is not conformance,
  and no manual audit is planned.
- **Pleasant is partly met.** The contract tests the behaviours listed; it does not test visual design, which is the
  app's, since the forms are unstyled.
- **Passkeys need JavaScript.** Progressive enhancement covers password and email flows only.
- **A replaced page leaves the contract.** UI an app writes itself is not covered by these tests.
- **WebKit runs need HTTPS on localhost.** Every test-cap cookie is `__Host-` and so `Secure`, and WebKit does not store
  or send `Secure` cookies to `http://localhost` (WebKit bug 232088, still open; MDN's compatibility data notes the
  same for Safari). The WebKit Playwright runs, and anyone developing in Safari, use `https://localhost` with a local
  certificate ([ADR 0026](0026-strict-defaults-and-deployment-mode.md)).
- **Playwright's virtual authenticator** is driven through the Chrome DevTools Protocol, so passkey browser runs are
  expected to cover Chromium only; Firefox and WebKit run the other flows. See Open 3.

## Open

1. **Passkey first versus enumeration.** Promise 9 offers a passkey first "when one exists", and promise 13 forbids
   revealing whether an account exists. If the server chooses the next step from the account's methods, it reveals
   both. Recommendation: passkey first comes from conditional-mediation autofill in the browser, before the identifier
   is sent; after the identifier, the server offers the same next step for every identifier.
2. **Keeping secret values after an error.** Promise 10 keeps values, but a server-rendered page that writes a password
   or code back into HTML puts a secret into a response. Recommendation: the React components keep every value in
   memory; the default pages keep the identifier and never write a password or code back.
3. **Passkeys on Firefox and WebKit.** The plan lists the virtual authenticator among the three-engine runs.
   Recommendation: state Chromium-only coverage for passkey browser runs, and rely on the WebAuthn L3 §16 vectors and
   the software authenticator ([ADR 0016](0016-protocol-conformance.md)) for the protocol on every engine.
4. **`returnTo` through the default pages.** The pages served by `auth.handle` (phase 3) post no `returnTo`, so a
   sign-in from a page ends at `/`. Recommendation: a page `GET` takes `returnTo` from its query, validates it as the
   routes do (ADR 0026 §5), and posts it back as a hidden field.
5. **Strings of the served pages.** The pages `auth.handle` serves use the default English messages; the form model
   takes replacements, but `createAuth` has no option to pass them. Recommendation: a `messages` option on `createAuth`
   in phase 7, alongside the React components.
6. **State written on a `GET`.** Opening `/auth/totp/enrol` begins an enrolment (an unconfirmed authenticator that
   expires in 10 minutes), and opening `/auth/step-up` opens a challenge. Neither changes what the session may do, and
   both need the session cookie, but a cross-site top-level navigation can still create them. Recommendation: keep
   them on `GET` for no-JavaScript pages, and revisit if an expired-record sweep (ADR 0002) shows them piling up.
