# 0019: Internal use, disclosure and distribution

## Status

Accepted (2026-11-15). The repository settings are applied in phase 1; the GitHub Release tarball is built in phase 9.
Answers handoff question 19.

Planned tests:

- `test/release/no-install-scripts.test.ts` (the packed `package.json` has no `preinstall`, `install`, `postinstall`
  or `prepare` that a consumer would run)
- `test/package/tarball-install.test.ts` (shared with [ADR 0004](0004-package-entries-and-capability-gates.md))
- `test/docs/no-public-security-claims.test.ts` (the README, the landing page and `specs/` contain no compliance,
  certification or pen-test claim)

The contract's existing `SecuritySecrets` and `PackedConsumer` checks also apply.

## Context

The owner wants test-cap for their own apps, as an alternative to Better Auth. The handoff assumed a public npm
package and asked for a positioning table against other auth products, a security disclosure policy, and whether any
part should stay private.

The plan answers with the owner's requirement 8: a public GitHub repository now, so the free review apps (CodeQL,
CodeRabbit, Socket, Scorecard) run on it, made private later. Internal use only: no outside users, not on npm, no
public security claims, no external pen test. The owner declined to reconsider the public repository or the pen test.

Two facts shape distribution. npm runs a package's `prepare` script when it installs from git but not when it
installs from a tarball URL. internal-package-contract (IPC) forbids install-time scripts.

## Decision

### 1. Internal use only, with no outside users

test-cap is built for the owner's apps. It has no support promise to anyone else, and the docs say so.

Why: the owner's requirement. It also sets the bar for every other decision here: the audience is internal readers.

### 2. A public repository now, private later

The repository `MaverickCER/test-cap` is public, set up with IPC `init --strict --github` (no adoption mode, ruleset
applied). It will be made private later. Anything pushed while it is public stays in forks and caches, so secrets are
never committed (`SecuritySecrets`), and test keys are generated at run time.

Why: the public phase buys the review apps for free. Treating every commit as permanently public is the only safe
assumption while it lasts.

### 3. Not on npm; installed from a GitHub Release tarball

`package.json` keeps `"private": true`, and apps install a prebuilt tarball from a GitHub Release by URL.
[ADR 0004](0004-package-entries-and-capability-gates.md) owns the mechanics: the install command, the artefact and why a
tarball rather than git.

Why: keeping it off npm matches internal use, and a prebuilt tarball runs nothing on install.

### 4. No install-time scripts

The published package has no script that runs on install. Everything a consumer needs is in the tarball's `dist/`.

Why: IPC forbids them, and an install script is code that runs with the installer's rights before anyone reviews it.

### 5. No public security claims, no positioning table, no external pen test

The README, the IPC landing page and `specs/` describe what is tested and what is not, for internal readers. They
never call test-cap compliant, certified or pen-tested, and they say what the free tooling (ZAP, fuzzing, CodeQL and
the rest) does not cover. The handoff's "How it differs" table is not written. There is no external pen test, by owner
decision.

Why: a public claim invites reliance from people the package does not serve, and the evidence behind any claim is
test-cap's own tests. A positioning table is for an audience test-cap does not have.

### 6. Disclosure while public

While the repository is public, a suspected vulnerability is reported through the repository's private vulnerability
reporting, as `SECURITY.md` (written by IPC `init`) already describes. Fixes go into the next release; only the
latest release receives them.

Why: the channel already exists, keeps reports out of public issues and costs nothing.

## Consequences

- Apps pin an exact release URL. Upgrading is a deliberate edit, not a range resolution.
- No npm provenance or npm advisory database covers test-cap; its GitHub Releases and the repository are the record.
- The landing page is public while the repository is, so its wording is held to the same no-claims rule.

## Limits

- Making the repository private later does not remove what was public: forks, caches and archived copies remain.
- Without an external pen test, test-cap's security evidence is its own: the attack catalogue, the free tooling and
  the review apps. The docs say what that does not cover.
- Install by URL depends on GitHub Releases being reachable from the app's build environment.

## Open

1. **The private-phase channel.** An owner question in the plan, recorded in
   [ADR 0004](0004-package-entries-and-capability-gates.md) (Open 4) with its recommendation; it decides how apps
   install once the public release URL stops working.
2. **The release workflow does not build a tarball yet.** The workflow IPC `init` wrote calls IPC's shared
   `release-npm-changesets.yml`, which skips a package marked `"private": true` ("is private; nothing to publish"),
   so no GitHub Release tarball is produced today. Recommendation: add a GitHub Release tarball path to IPC's shared
   release flow for private packages (keeping the contract-run check it already does), rather than a test-cap-only
   workflow.
3. **Disclosure once private.** GitHub documents private vulnerability reporting for public repositories. Once
   test-cap is private, `SECURITY.md` needs another channel. Recommendation: with no outside users, a private issue in
   the repository itself, and `SECURITY.md` updated in the same change that makes the repository private.
4. **`SECURITY.md` wording.** It speaks of "the latest published version". Recommendation: "the latest GitHub
   Release", so it matches section 3.
