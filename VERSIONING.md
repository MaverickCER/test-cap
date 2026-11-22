# Versioning

`test-cap` follows [Semantic Versioning](https://semver.org). Versions are produced by
[Changesets](https://github.com/changesets/changesets). The release pull request sets the version. A version
edited by hand on another branch fails `ApiContract` and `SurfaceContract`, whose baselines record the released
one.

- **Patch**: bug fixes and internal changes that do not alter the public API.
- **Minor**: backwards-compatible additions. While the version is `0.x`, a breaking change is
  also released as a minor, and says so in its changeset.
- **Major**: breaking changes to the public API, once the package is `1.0.0` or later.

The public API is whatever `package.json`'s `exports` map names. Anything else is private and may
change in any release.

## What the version number covers

Two checks compare each branch with the last release and fail unless its changeset declares a
large enough bump:

- **TypeScript API**: every entry point in `exports` that exposes types (`ApiContract`).
- **Everything else a user can depend on** (`SurfaceContract`):
  - the `--help` text and exit code of each `bin`, and of each command its help lists;
  - every JSON file `exports` serves (schemas and shared configs);
  - the inputs, secrets and outputs of the root `action.yml` and of each reusable workflow;
  - the headings of generated documents, when `package.json` lists their renderers under
    `internal-package-contract.surfaceRenderers`.

  Removing or changing any of them is a breaking change. Adding an optional flag, property or input is a
  minor change from `1.0.0`. Rewording a description is a patch.

Neither check sees a change in behaviour behind an unchanged signature or `--help` text, or in the
files a command writes. Those are judged in review, and a changeset says so when they matter.

## Surfaces

| Surface                                                           | Tier    | What a change means                                                                                                                     |
| ----------------------------------------------------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Every entry in `exports`                                          | public  | Versioned as above. Before `1.0.0`, a breaking change is a minor and says so.                                                           |
| The `/auth/*` routes, their fields, replies and error codes       | public  | Versioned like the API, because apps and the default pages depend on them. Review judges it; no check compares them with a release.     |
| The session and CSRF cookie names                                 | public  | A rename signs every user out, so it is a breaking change.                                                                              |
| Entries not yet in `exports` (the SQL store, the conformance kit) | private | May change in any release until a capability gate adds them ([ADR 0004](specs/decisions/0004-package-entries-and-capability-gates.md)). |
| Anything under `src/` not reachable from `exports`                | private | May change in any release.                                                                                                              |

There is no experimental tier: a capability enters `exports` only when its gate passes.
