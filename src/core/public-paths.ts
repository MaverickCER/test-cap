/**
 * The public-path list of deny by default (ADR 0024 §2 and Open 1). An entry matches the clean raw path exactly, so
 * `"/"` is the root only; a prefix needs an explicit trailing wildcard, `"/blog/*"`, which matches `/blog/` followed
 * by one or more segments. Matching is case-sensitive and never normalises: `/About` is not `/about`, and an ambiguous
 * path never reaches this check, because the core refuses it with a 400 first (ADR 0003 §2).
 */

import { ConfigError } from "./errors.js"

const SEGMENT = "[A-Za-z0-9_~-][A-Za-z0-9._~-]*"
const EXACT = new RegExp(`^(?:/|(?:/${SEGMENT})+)$`)
const WILDCARD = new RegExp(`^((?:/${SEGMENT})*)/\\*$`)

/** Compiles the list into a matcher; a malformed entry is a `ConfigError`, and every one is named at once. */
export function compilePublicPaths(entries: readonly string[]): (path: string) => boolean {
  const wildcards = entries.map((entry) => WILDCARD.exec(entry))
  // The group always takes part in a match, so it is a string, empty for "/*".
  const prefixes = wildcards
    .filter((match) => match !== null)
    .map((match) => `${match[1] as string}/`)
  const exact = new Set(entries.filter((entry) => EXACT.test(entry)))
  const problems = entries
    .filter((entry, index) => wildcards[index] === null && !exact.has(entry))
    .map(
      (entry) =>
        `The public path "${entry}" must be a clean path such as /about, or end in /* such as /blog/*.`,
    )
  if (problems.length > 0) throw new ConfigError(problems)
  return (path) =>
    exact.has(path) ||
    prefixes.some((prefix) => path.length > prefix.length && path.startsWith(prefix))
}
