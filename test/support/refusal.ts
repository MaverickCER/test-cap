import { TransportError } from "../../src/core/errors.js"

function describeRefusal(error: unknown): string {
  if (error instanceof TransportError)
    return `${error.code} ${String(error.status)}: ${error.message}`
  throw error
}

/** Runs `run` and describes the `TransportError` it throws as `code status: message`. */
export function refusal(run: () => unknown): string {
  try {
    run()
  } catch (error) {
    return describeRefusal(error)
  }
  throw new Error("expected a TransportError")
}

/** The same as {@link refusal}, for a function that returns a promise. */
export async function refusalAsync(run: () => Promise<unknown>): Promise<string> {
  try {
    await run()
  } catch (error) {
    return describeRefusal(error)
  }
  throw new Error("expected a TransportError")
}
