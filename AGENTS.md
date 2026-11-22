# AGENTS.md

Rules for AI coding agents working in `test-cap`. A human contributor follows the same rules;
[CONTRIBUTING.md](CONTRIBUTING.md) has the reasons.

## Loop

1. Run `npm ci` once per clone.
2. Write the test first and run it. It fails, for the reason you expect. A bug fix starts with a test that
   reproduces the bug.
3. Write the code that makes it pass. `npm run verify` is the fast loop.
4. Run `npm run contract`, the full gate CI runs. The change is done when it passes. Report any check you
   could not run, with its cause.

`npx internal-package-contract --help` lists the commands. `npx internal-package-contract doctor` says what is
set up and what is left.

## Hard rules

- **Meet every gate as it stands.** Commit and push with the hooks running (never `--no-verify`), and keep
  every workflow and threshold as it is. When a gate fails, fix the cause. When you think the gate is wrong,
  say so in the pull request and leave the gate in place.
- **Commit with Conventional Commits and no `Co-Authored-By:` trailer.** The commit-msg hook and the `Commits`
  check reject a message that breaks either.
- **Change a generated file through its source.** `dist/` comes from `src/` (`npm run build`).
  `docs/api-report/` and `docs/api/` come from TSDoc (`npm run docs:api:report`, `npm run docs:api`). A region
  between `<!-- ipc:begin -->` and `<!-- ipc:end -->` comes from `package.json` and `docs/surface.json`
  (`npx internal-package-contract generate`). `docs/ENVIRONMENT.md` comes from `ci/env.schema.ts`
  (`npm run docs:env`).
- **Propose the version bump; the maintainer sets it.** Add a changeset (`.changeset/<name>.md`) at the level
  [VERSIONING.md](VERSIONING.md) gives, and name that level in the pull request. `ApiContract` and
  `SurfaceContract` fail a level smaller than the change.
- **Land every change through a pull request.** The release workflow versions, tags and publishes after a
  person merges the release pull request.

## Conventions

- Commit headers are imperative and lowercase. Keep header and body lines to 100 characters.
- A suppression comment (`eslint-disable`, `@ts-expect-error`, `// Stryker disable`) says why, on the
  same line, in words a reviewer can check.
- The public API is what `package.json` `exports` lists. Everything else can change in any release.

## Public API map

One row per entry point `package.json` exports. The table is generated: describe a new entry point in
`docs/surface.json`, then run `npx internal-package-contract generate`.

<!-- ipc:begin entry-points -->

| Export                    | Source                         | Environment                                                                                          | Tier   | Purpose                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------------- | ------------------------------ | ---------------------------------------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `test-cap`                | `src/`                         | isomorphic, one runtime dependency (hash-wasm)                                                       | Stable | `createAuth` and `defineAuthPolicy`, the `Auth` it returns and the types its signature needs; the `PlainRequest` and `PlainResponse` transport types, the `AuthStore` port and its record types, `Clock`, `RandomSource`, `DeploymentMode`, the `TransportError` and `ConfigError` classes, and the OCSF security event types.                                                                                              |
| `test-cap/express`        | `src/adapters/express/`        | Node, Express 5 (typed structurally; no dependency on express)                                       | Stable | `expressAuth(auth, { public })`: mounts test-cap on an Express app, serves `/auth/*` from the raw request stream, and protects every other route at the default requirement unless it is listed as public.                                                                                                                                                                                                                  |
| `test-cap/fetch`          | `src/adapters/fetch/`          | Web Request and Response globals; its tests run on Node, and Bun and Deno are planned for phase 6    | Stable | `withAuth(auth, handler, { public, clientAddress })`: wraps an app's fetch handler, serves `/auth/*` and protects every other route at the default requirement unless it is listed as public; `fetchAuth(auth)` serves the `/auth/*` routes alone and answers `null` for any other path.                                                                                                                                    |
| `test-cap/next`           | `src/adapters/next/`           | Next.js 16 App Router on the Node.js runtime (typed structurally; no dependency on next)             | Stable | `nextAuthHandler(auth)` for `app/auth/[...path]/route.ts`; `nextServerAuth(auth, { headers })`, the authoritative check for route handlers, server functions and the data-access layer; `nextProxy(auth, { public })`, an optional proxy for early redirects that is not protection.                                                                                                                                        |
| `test-cap/tanstack-start` | `src/adapters/tanstack-start/` | Web Request and Response, TanStack Start 1.169 (typed structurally; no dependency on TanStack Start) | Stable | `tanstackStartMiddleware(auth, { public })`, the server function of a global request middleware that protects every route and server function call at the default requirement unless its path is listed as public, and puts the subject in `context.auth`; `tanstackStartAuth(auth)`, whose `handlers` serve the `/auth/$` server route and whose `require` and `session` let a server function check a requirement itself. |
| `test-cap/store/memory`   | `src/store/memory.ts`          | isomorphic, no dependencies; development and test only                                               | Stable | `memoryStore()`: the reference `AuthStore`, kept in one process's memory. It declares itself not durable, so production and staging refuse to start with it.                                                                                                                                                                                                                                                                |

<!-- ipc:end entry-points -->
