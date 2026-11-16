# 0028: SAML library and its own gate

## Status

Accepted (2026-11-15). Implemented in phase 8, as its last capability. Flow: F12 (SAML SP sign-in). Pinned by:

- `test/saml/interop-local-idp.test.ts`
- `test/saml/post-binding-tx-cookie.test.ts`
- `test/attacks/saml/signature-wrapping.test.ts`
- `test/attacks/saml/multiple-signed-info.test.ts`
- `test/attacks/saml/digest-comment-injection.test.ts`
- `test/attacks/saml/comment-node-splitting.test.ts`
- `test/attacks/saml/unsigned-assertion.test.ts`
- `test/attacks/saml/attacker-key-in-message.test.ts`
- `test/attacks/saml/weak-algorithms.test.ts`
- `test/attacks/saml/audience-and-destination.test.ts`
- `test/attacks/saml/replay-in-response-to.test.ts`
- `test/attacks/saml/xml-entity-and-size.test.ts`
- `test/surface/saml-isolation.test.ts`
- `test/supply-chain/xml-crypto-floor.test.ts`
- `test/cross-runtime/saml-node-only.test.ts`

## Context

Owner requirement 5 asks for every secure, free method, and enterprise buyers expect SAML 2.0 single sign-on. SAML is
also the method with the worst security record in the JavaScript ecosystem, because XML signatures are easy to verify
on one part of a document while the application reads another (research raw notes, "SAML library advisories"):

- **`@node-saml/node-saml`**: CVE-2022-39300 (high), CVE-2023-40178 (medium), and two critical 2025 advisories,
  CVE-2025-54369 (authentication bypass) and CVE-2025-54419 (signature verification), both fixed in 5.1.0. The latest
  release is 5.2.0 (2026-10-26). It depends on `xml-crypto` `^6.4` and `@xmldom/xmldom` `^0.8.15`.
- **`xml-crypto`**: CVE-2024-32962 (signature spoofing), CVE-2025-29774 (multiple `SignedInfo` references) and
  CVE-2025-29775 (`DigestValue` comment), all critical.
- **`@xmldom/xmldom`**: 23 advisories, 16 of them in 2026 (injection, ReDoS, quadratic DoS).
- **`samlify`**: nine advisories on 2026-10-20 alone, among them an attacker certificate accepted from `RSAKeyValue`
  metadata, `AudienceRestriction` not enforced, signatures not bound to the parsed message, no `InResponseTo` check,
  comment-node splitting, signature wrapping, and RSA-1.5 and 3DES accepted; earlier, CVE-2025-47949 (signature
  wrapping).

Owner requirement 1 forbids writing the protocol by hand, so the choice is between these libraries.

## Decision

### 1. `@node-saml/node-saml` 5.2, and `samlify` is rejected

test-cap's SAML service provider uses `@node-saml/node-saml` 5.2.

Why: both libraries have serious histories, but node-saml's critical 2025 issues are fixed and its maintainers also
maintain `xml-crypto`. `samlify`'s October 2026 batch shows open classes (audience, replay, algorithm choice) that a
caller cannot reliably close from outside.

### 2. The `xml-crypto` floor is pinned

test-cap declares a minimum `xml-crypto` version no lower than the range node-saml 5.2 requires, and a supply-chain
test fails when the version that would load is below it.

Why: the signature checks that matter most live in `xml-crypto`, and a transitive range alone could resolve to a
release with a known bypass.

### 3. Last phase, and its own capability gate

SAML is the last capability built in phase 8. It enters `exports` only when its own gate passes:

- **Interop** against a local test identity provider in CI: sign-in with the POST binding, signed responses and signed
  assertions.
- **Every XML-signature advisory class as a negative test**, each one under `test/attacks/saml/`: signature wrapping,
  multiple `SignedInfo`, comments inside `DigestValue` or `NameID`, an unsigned assertion inside a signed response, a
  key or certificate supplied in the message instead of the configured one, weak algorithms (SHA-1 digests, RSA-1.5,
  3DES), audience, recipient and destination mismatches, replay of a response or its `InResponseTo`, and XML entity
  and size attacks.

Why: a capability with this history earns its place by failing every known attack, not by the library's word. Building
it last means every other capability ships without waiting on it.

Override: none. An app without SAML is unaffected by the gate.

### 4. A separate entry that only SAML apps load

SAML lives in an entry of its own. Nothing in the main entry or any other entry imports it, and a test checks the built
import graph. The entry's name and how `@node-saml/node-saml` is installed are open in
[ADR 0004](0004-package-entries-and-capability-gates.md) (Open 1, which recommends `test-cap/saml` and an optional peer
dependency).

Why: an app without SAML should never load `xml-crypto` or `@xmldom/xmldom`, so their advisories cannot reach it.

### 5. Node only

The SAML entry runs on Node only ([ADR 0023](0023-runtime-support-per-capability.md), section 4).

Why: its library depends on Node, and no Bun or Deno job proves otherwise.

### 6. The POST binding uses the federation transaction cookie

An identity provider returns a SAML response by a cross-site `POST`, and a cookie set with an explicit `SameSite=Lax` is
not sent on a cross-site `POST`. The round trip therefore uses the federation transaction cookie `__Host-test-cap-tx`
(SameSite=None, 10 minutes, a random id only), bound to a single-use federation transaction that holds the
`InResponseTo` value. The session cookie keeps SameSite=Lax. [ADR 0006](0006-sessions-and-cookies.md) owns both cookies.

Why: the transaction cookie carries nothing but an id, lives minutes, and is spent on first use, so relaxing its
SameSite costs nothing the session cookie relies on.

### 7. Keys and configuration

The service provider signs with `AUTH_SAML_SP_PRIVATE_KEY` and publishes `AUTH_SAML_SP_CERT`
([ADR 0022](0022-environment-variables.md)). Each tenant configures its own identity provider
([ADR 0012](0012-tenancy.md)).

## Consequences

- Enterprise customers get SAML single sign-on, after every other method.
- Apps without SAML carry none of its dependencies' risk.
- A new advisory in node-saml, `xml-crypto` or `@xmldom/xmldom` becomes a new negative test before the floor moves.

## Limits

- **A library with this history may have undisclosed flaws.** The gate proves the known classes fail; it cannot prove
  there are no others.
- **The local test identity provider is not every identity provider.** Interop with a customer's provider is shown
  only when that customer connects.
- **Bun, Deno and edge runtimes are unsupported.**
- **What a SAML sign-in is worth** follows the trust config, as OIDC does
  ([ADR 0005](0005-policy-and-evidence-based-assurance.md)); see Open 3.

## Open

1. **The exact `xml-crypto` floor and how it is enforced.** npm `overrides` in test-cap's own `package.json` do not
   apply in an app that installs the tarball. Recommendation: declare `xml-crypto` as a direct dependency with the
   floor (taken from the advisory database at the start of phase 8, and never below node-saml 5.2's `^6.4`), and have
   the SAML entry check the loaded version when it is created.
2. **Which local test identity provider.** Recommendation: Keycloak in a Docker service container, which can sign
   responses, assertions or both.
3. **Mapping SAML authentication context.** The trust config maps OIDC `acr` and `amr`. Recommendation: it maps SAML's
   `AuthnContextClassRef` the same way, with a maximum authentication age, so an unmapped context stays AAL1.
4. **Unsolicited responses.** A response with no `InResponseTo` (IdP-initiated sign-in) has no federation transaction
   to bind to. Recommendation: reject it by default.
