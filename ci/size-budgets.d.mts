/** One gzip budget, read by `internal-package-contract tool size`. */
export interface SizeBudget {
  /** A short name for what is measured. */
  readonly label: string
  /** For an `exports` entry, its ESM file from the package root; absent for the default pages' assets. */
  readonly entry?: string
  /** The file the Size check gzips: the entry with every chunk it imports, or the served page assets. */
  readonly file: string
  /** The largest allowed gzip size, in bytes. */
  readonly maxGzipBytes: number
}

/** The first measured gzip size of each server entry with its chunks, in bytes. */
export declare const MEASURED: Readonly<Record<string, number>>

/** The first measurement plus 10 percent, rounded up to a whole byte. */
export declare function plusTenPercent(bytes: number): number

/** The file and every dist/ file it reaches through relative imports, each once, the entry first. */
export declare function closure(file: string): string[]

declare const budgets: readonly SizeBudget[]
export default budgets
