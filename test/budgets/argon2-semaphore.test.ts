import { describe, expect, it } from "vitest"
import { createSemaphore, QueueFullError } from "../../src/methods/password/semaphore.js"
import { within } from "../support/within.js"

/** A task the test finishes by hand. */
function gate(): { promise: Promise<string>; open: (value: string) => void } {
  let open: (value: string) => void = () => undefined
  const promise = new Promise<string>((resolve) => {
    open = resolve
  })
  return { promise, open }
}

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0))

describe("createSemaphore", () => {
  it("refuses a limit or queue bound that is not a whole number in range", () => {
    expect(() => createSemaphore(0, 1)).toThrow(
      new RangeError("The concurrency limit must be a whole number of at least 1."),
    )
    expect(() => createSemaphore(1.5, 1)).toThrow(RangeError)
    expect(() => createSemaphore(1, -1)).toThrow(
      new RangeError("The queue limit must be a whole number of at least 0."),
    )
    expect(() => createSemaphore(1, 0.5)).toThrow(RangeError)
    expect(createSemaphore(1, 0).limit).toBe(1)
  })

  it("runs no more than the limit at once and queues the rest in order", async () => {
    const semaphore = createSemaphore(2, 2)
    const gates = [gate(), gate(), gate(), gate()]
    const started: number[] = []
    const results = gates.map((g, index) =>
      semaphore.run(() => {
        started.push(index)
        return g.promise
      }),
    )
    await tick()
    expect(started).toEqual([0, 1])
    expect(semaphore.active).toBe(2)
    expect(semaphore.waiting).toBe(2)
    gates[1]?.open("b")
    await tick()
    expect(started).toEqual([0, 1, 2])
    expect(semaphore.active).toBe(2)
    expect(semaphore.waiting).toBe(1)
    gates[0]?.open("a")
    gates[2]?.open("c")
    gates[3]?.open("d")
    expect(await within(Promise.all(results), 500)).toEqual(["a", "b", "c", "d"])
    expect(semaphore.active).toBe(0)
    expect(semaphore.waiting).toBe(0)
  })

  it("refuses a task when the queue is full, without running it", async () => {
    const semaphore = createSemaphore(1, 1)
    const first = gate()
    const second = gate()
    const running = semaphore.run(() => first.promise)
    const queued = semaphore.run(() => second.promise)
    let ran = false
    await expect(
      within(
        semaphore.run(() => {
          ran = true
          return Promise.resolve("x")
        }),
        500,
      ),
    ).rejects.toThrow(new QueueFullError("The hashing queue is full."))
    expect(ran).toBe(false)
    expect(semaphore.waiting).toBe(1)
    first.open("1")
    second.open("2")
    expect(await within(Promise.all([running, queued]), 500)).toEqual(["1", "2"])
  })

  it("frees the slot when a task fails", async () => {
    const semaphore = createSemaphore(1, 0)
    await expect(
      within(
        semaphore.run(() => Promise.reject(new Error("boom"))),
        500,
      ),
    ).rejects.toThrow("boom")
    expect(semaphore.active).toBe(0)
    expect(
      await within(
        semaphore.run(() => Promise.resolve("next")),
        500,
      ),
    ).toBe("next")
  })

  it("names its error", () => {
    expect(new QueueFullError("m").name).toBe("QueueFullError")
  })
})
