/** One gzip budget for one entry file, read by `internal-package-contract tool size`. */
export interface SizeBudget {
  /** A short name for the entry. */
  readonly label: string
  /** The entry's ESM file, from the package root. */
  readonly file: string
  /** The largest allowed gzip size, in bytes. */
  readonly maxGzipBytes: number
}

declare const budgets: readonly SizeBudget[]
export default budgets
