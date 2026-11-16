/** A check that exercises one value export of dist/index.js and calls `check` with each condition it asserts. */
export type ExportCheck = (
  dist: Record<string, unknown>,
  check: (condition: unknown, message: string) => void,
) => void | Promise<void>

/** One check per value export of dist/index.js, keyed by the export's name. */
export declare const CHECKS: Readonly<Record<string, ExportCheck>>
