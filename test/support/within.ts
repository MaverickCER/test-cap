/**
 * Settles with `promise`, or rejects when it has not settled after `ms` of real time. A mutant that makes a promise
 * hang then fails a test fast instead of timing the run out.
 */
export function within<T>(promise: Promise<T>, ms = 2_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const hung = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`did not settle within ${ms} ms`))
    }, ms)
  })
  return Promise.race([promise, hung]).finally(() => {
    clearTimeout(timer)
  })
}
