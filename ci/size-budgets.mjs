// Gzip size budgets, one per `exports` entry, read by `internal-package-contract tool size` (the `Size` check).
//
// The numbers are the plan's (ADR 0018): 6 KB for the core entry and 3 KB for each method entry, excluding the
// libraries a method delegates to, which are dependencies rather than part of the entry file. The budget measures
// the entry file, not an app's bundle. Add a line here in the same pull request that adds an `exports` entry.
export default [{ label: "core", file: "dist/index.js", maxGzipBytes: 6 * 1024 }]
