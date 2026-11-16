/**
 * The error model. A request the core refuses before any flow runs raises a `TransportError`, which the dispatcher
 * turns into its status code. A configuration that cannot run raises a `ConfigError` at startup, listing every problem
 * at once (ADR 0003, ADR 0026).
 */

/** Why the transport refused a request. */
export type TransportErrorCode =
  | "aborted"
  | "ambiguous-header"
  | "body-too-large"
  | "duplicate-field"
  | "invalid-path"
  | "malformed-body"
  | "too-many-fields"
  | "unsupported-media-type"

const STATUS: Readonly<Record<TransportErrorCode, number>> = {
  aborted: 400,
  "ambiguous-header": 400,
  "body-too-large": 413,
  "duplicate-field": 400,
  "invalid-path": 400,
  "malformed-body": 400,
  "too-many-fields": 400,
  "unsupported-media-type": 415,
}

/** A request refused by the transport. The message is for logs; responses carry only the code. */
export class TransportError extends Error {
  /** Why the request was refused; the only detail a response may carry. */
  readonly code: TransportErrorCode
  /** The HTTP status the dispatcher answers with: 413 for `body-too-large`, 415 for `unsupported-media-type`, else 400. */
  readonly status: number

  constructor(code: TransportErrorCode, message: string) {
    super(message)
    this.name = "TransportError"
    this.code = code
    this.status = STATUS[code]
  }
}

/** A configuration test-cap refuses to start with. `problems` lists every one found, not only the first. */
export class ConfigError extends Error {
  /** One sentence per failed check, in the order found; never empty. */
  readonly problems: readonly string[]

  constructor(problems: readonly string[]) {
    super(`test-cap refused to start:\n${problems.map((problem) => `- ${problem}`).join("\n")}`)
    this.name = "ConfigError"
    this.problems = problems
  }
}
