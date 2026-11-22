/**
 * The concurrency semaphore that bounds argon2id hashing (ADR 0018 §2). At most `limit` tasks run at once; up to
 * `queueLimit` more wait their turn in order, and a task beyond that is refused before it runs.
 */

/** A task was refused because the queue was full. The caller answers with the throttled reply (ADR 0009). */
export class QueueFullError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "QueueFullError"
  }
}

/** A bound on how many tasks run at once. */
export interface Semaphore {
  /** How many tasks may run at once. */
  readonly limit: number
  /** Tasks running now. */
  readonly active: number
  /** Tasks waiting for a slot. */
  readonly waiting: number
  /** Runs `task` when a slot is free; rejects with `QueueFullError` without running it when the queue is full. */
  run<T>(task: () => Promise<T>): Promise<T>
}

function assertBound(value: number, what: string, min: number): void {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new RangeError(`${what} must be a whole number of at least ${min}.`)
  }
}

/** A semaphore of `limit` slots with a queue of at most `queueLimit` waiting tasks. */
export function createSemaphore(limit: number, queueLimit: number): Semaphore {
  assertBound(limit, "The concurrency limit", 1)
  assertBound(queueLimit, "The queue limit", 0)
  let active = 0
  const queue: (() => void)[] = []

  const acquire = async (): Promise<void> => {
    if (active < limit) {
      active += 1
      return
    }
    if (queue.length >= queueLimit) throw new QueueFullError("The hashing queue is full.")
    // The slot is handed over by `release`, so `active` stays the same.
    await new Promise<void>((resolve) => queue.push(resolve))
  }

  const release = (): void => {
    const next = queue.shift()
    if (next === undefined) active -= 1
    else next()
  }

  return {
    limit,
    get active() {
      return active
    },
    get waiting() {
      return queue.length
    },
    async run(task) {
      await acquire()
      try {
        return await task()
      } finally {
        release()
      }
    },
  }
}
