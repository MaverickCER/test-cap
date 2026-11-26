# 0016: Protocol conformance

## Status

Accepted (2026-11-15). Implemented across phases: the RFC 4226 and RFC 6238 vectors in phase 3 (TOTP); the WebAuthn
vectors and OIDC interoperability in phase 5; the Playwright virtual authenticator in phase 7; the SAML test IdP and
negative cases in phase 8; the OpenID conformance suite in phase 9. The ZAP scans of section 8 run in CI from
phase 4 (the `zap` job, against the slice behind Express); the Playwright attack scripts arrive with Playwright in
phase 7; both become a release gate in phase 9. Answers [handoff
question](../../GLOSSARY.md) 16.

Planned tests:

- `test/otp/hotp-rfc4226-vectors.test.ts` and `test/otp/totp-rfc6238-vectors.test.ts` (owned by
  [ADR 0027](0027-otp-on-web-crypto-and-encrypted-secrets.md))
- `test/protocols/webauthn-l3-vectors.test.ts`
- `test/e2e/passkey-virtual-authenticator.spec.ts` (Playwright, three engines)
- `test/protocols/oidc-provider-interop.test.ts` (against `oidc-provider`)
- `test/saml/interop-local-idp.test.ts` and the SAML attack tests (listed and owned by
  [ADR 0028](0028-saml-library-and-its-own-gate.md))
- `test/support/frozen-time.ts` (the test-time clock shim of section 6, with its own tests)
- the `openid-conformance` CI job (section 2)
- the `zap` CI job (section 8: ZAP baseline and active scans against `ci/zap/server.mjs`, the slice behind Express)
- `test/e2e/attack-scripts.spec.ts` (section 8: Playwright attack scripts against the same example)

The recommendations under Open are provisional defaults until the owner decides.

## Context

test-cap delegates protocols to libraries ([ADR 0001](0001-compose-audited-primitives-instead-of-better-auth.md)):
`oauth4webapi` for OIDC, `@simplewebauthn/server` for WebAuthn, Web Crypto HMAC for HOTP and TOTP, and
`@node-saml/node-saml` for SAML ([ADR 0028](0028-saml-library-and-its-own-gate.md)). A library that is correct on its
own can still be used wrongly: a check skipped, an option left at an unsafe value, a parameter passed from the wrong
place. Unit tests written by the same hands that wired the library share the same blind spots.

Each protocol has an outside reference that does not share them: test vectors published with the standard, a
conformance suite run by the standard's body, or an independent implementation of the other side. The handoff asked
how the build proves protocol correctness and which checks run on every change and which at release.

Two libraries read the clock themselves. `oauth4webapi` calls `Date.now()` internally; its `clockSkew` option offsets
that reading but cannot replace it. `@simplewebauthn/server` also calls `Date.now()`. test-cap's own clock is
injectable, but these calls do not go through it.

## Decision

### 1. Each protocol is checked against an outside reference

| Protocol      | Reference                                                                                      |
| ------------- | ---------------------------------------------------------------------------------------------- |
| HOTP          | RFC 4226 Appendix D test values                                                                |
| TOTP          | RFC 6238 Appendix B test vectors, for every hash algorithm the module accepts                  |
| WebAuthn      | WebAuthn Level 3 §16 test vectors; Playwright's virtual authenticator in three browser engines |
| OIDC (RP)     | `oidc-provider` as the other side; the OpenID conformance suite                                |
| SAML 2.0 (SP) | a local test IdP; every XML-signature advisory class as a negative case                        |

Why: an outside reference catches a misunderstanding of the standard, which a test written from the same
understanding cannot.

### 2. The OpenID conformance suite runs in Docker at release

The OpenID Foundation's conformance suite (v5.3.4) is started with `docker compose -f docker-compose-prebuilt.yml up`
and runs the relying-party test plans `oidcc-client-basic-certification-test-plan` and
`oidcc-client-config-certification-test-plan` against test-cap's OIDC sign-in. Every module in both plans must pass. It
runs in the release verification of phase 9, before the GitHub Release tarball is built
([ADR 0019](0019-internal-use-disclosure-and-distribution.md)).

Why: the suite is the reference the certified libraries are measured against. Running it against test-cap, not only
trusting `oauth4webapi`'s certification, checks test-cap's use of the library: state, nonce, PKCE, issuer and
`acr` handling.

### 3. Vectors and local interoperability run on every pull request

The RFC vectors, the WebAuthn §16 vectors, `oidc-provider` interoperability, the virtual-authenticator browser tests
and, from phase 8, the SAML test-IdP tests run in the contract gate of every pull request.

Why: they are fast, need no outside service and catch regressions at the change that causes them.

### 4. WebAuthn: vectors plus a real browser

The §16 vectors check that verification accepts what the standard says is valid. Playwright's virtual authenticator
drives registration and authentication through Chromium, Firefox and WebKit, including user verification on and off,
so the UV rule of [ADR 0005](0005-policy-and-evidence-based-assurance.md) is checked end to end.

Why: vectors prove the server side; only a browser proves that `test-cap/client` and the server agree.

### 5. SAML: a local IdP and every advisory class as a negative case

SAML is checked against a test IdP that runs locally in CI, and every XML-signature advisory class of
`@node-saml/node-saml`, `xml-crypto`, `@xmldom/xmldom` and the rejected `samlify` is a negative test that must be
refused. [ADR 0028](0028-saml-library-and-its-own-gate.md) owns the list of classes and their tests; this ADR places
them in the per-pull-request gate from phase 8 onwards.

Why: SAML's failures come from XML signature handling, and its libraries have a long advisory history. The negative
cases are the reference that matters most for it.

### 6. Tests control the clock the libraries read

Unit and interoperability tests set the libraries' clock options (`clockSkew` for `oauth4webapi`) and also install a
test-time shim of the global `Date.now()`, so a library's own reading of the clock agrees with test-cap's injected
clock. The shim is test support only; production code never patches a global.

Why: without the shim, expiry and skew cases depend on wall-clock time, so they are flaky, and mutation testing
cannot kill time-dependent mutants.

### 7. Every ID token's signature is verified

`oauth4webapi` does not verify the signature of an ID token it receives from the token endpoint over TLS; its own type
declarations say so, because OpenID Connect Core allows a client to rely on TLS there. test-cap verifies every ID
token anyway: it calls `validateApplicationLevelSignature` on each one, against the issuer's JWKS and a per-issuer
algorithm allowlist from the trust config ([ADR 0008](0008-account-linking.md)). `none` and any symmetric algorithm
are never on the list.

Why: ASVS 5.0 6.8.2 and 9.1.1 require the signature to be checked every time a token is used. A certified library's
default is the protocol's minimum, not test-cap's bar.

Override: none. An issuer whose tokens cannot be verified is not added to the trust config.

Planned tests: `test/attacks/id-token-unsigned-or-alg-confusion.test.ts`,
`test/oidc/id-token-signature.test.ts`.

### 8. ZAP and Playwright attack scripts gate the release

Two free tools attack a running example app (one of phase 7's examples, or the phase 3 slice before those exist):

- **ZAP**, the OWASP Zed Attack Proxy, runs a baseline scan (passive checks) and an active scan (injected attacks)
  against the default pages and every `/auth/*` route;
- **Playwright attack scripts** drive real browsers through the attacks a scanner cannot model, such as a cross-site
  form post, a framed sign-in page and a replayed callback.

The first scan runs against the slice in phase 4 (Hardening), and its findings are fixed or recorded there. From phase 9
the scans are a release gate: release verification fails when ZAP reports any alert at risk medium or above, or when
an attack script succeeds. A false positive is recorded with its reason in the release report, never silenced in the
tool's configuration alone.

Why: the plan lists ZAP and Playwright attack scripts among the free tooling and requires "nothing at medium or above"
at release. A scanner tests the deployed behaviour (headers, cookies, redirects) that unit tests reach only piece by
piece.

Override: none.

## Consequences

- A change that breaks a protocol fails on its own pull request, except for the cases only the OpenID suite covers,
  which fail at release.
- The release workflow needs Docker and a few minutes for the OpenID suite.

## Limits

- The OpenID suite runs as the plan sets it, at release; a regression only it catches can sit on the main branch
  until then (see Open 1).
- The conformance suite covers the relying-party plans named above. FAPI, logout and dynamic registration plans are
  not run.
- WebAuthn vectors and a virtual authenticator are not real devices. Attestation from specific hardware models, and
  platform quirks of real authenticators, are not tested.
- SAML is checked against one test IdP. Interoperability with every enterprise IdP is not claimed, and SAML is
  Node-only ([ADR 0023](0023-runtime-support-per-capability.md)).
- ZAP finds the classes its rules know, against the routes it reaches. A clean scan is evidence for those rules on
  that example app, not for every deployment, and the phase 4 scan gates nothing until phase 9.
- None of this is a pen test or a certification. test-cap is not submitted for OpenID certification.

## Open

1. **A weekly OpenID suite run.** The plan places the suite at release verification only; `oauth4webapi`'s maintainer
   runs it weekly. Recommendation: also run it weekly on a schedule against the main branch, so a regression or a
   suite update surfaces between releases.
