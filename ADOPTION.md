# Adopting test-cap

<!-- ipc:prompt: describe, step by step, how a consumer adopts this package: install, minimal configuration, the first thing to run, and how to roll it out gradually. -->

## Requirements

- Node.js 22 or later

## Install

```sh
npm install test-cap
```

## What installing it adds

Generated from `package.json` by `internal-package-contract generate`; give each dependency's reason in
`docs/surface.json` under `"dependencies"`.

<!-- ipc:begin dependencies -->

Installing `test-cap` installs no other packages. It names 1 optional peer, which you install yourself when you use the part that needs it.

| Package                | Kind          | Range    | Why                                                                                                                                                                                                |
| ---------------------- | ------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@maverickcer/env-cap` | optional peer | `^0.7.7` | Optional peer. Only `src/env.schema.ts` imports it, so env-cap can document and validate test-cap's variables in an app that uses env-cap; without it, `createAuth` takes plain values (ADR 0022). |

<!-- ipc:end dependencies -->
