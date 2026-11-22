import { ORIGIN, type Reply, type Transport } from "./auth.js"

/** The Web `Request` a test request becomes, at `ORIGIN`, with every header line as given. */
export function webRequest(
  outgoing: Parameters<Transport>[0],
  init: { readonly signal?: AbortSignal } = {},
): Request {
  const headers = new Headers()
  for (const [name, value] of outgoing.headers ?? []) headers.append(name, value)
  return new Request(`${ORIGIN}${outgoing.path}`, {
    method: outgoing.method,
    headers,
    body: outgoing.body ?? null,
    signal: init.signal ?? null,
  })
}

/** A reply read from a Web `Response`. */
export async function replyOfResponse(response: Response): Promise<Reply> {
  const text = await response.text()
  return {
    status: response.status,
    headers: response.headers,
    text,
    json: text === "" ? undefined : (JSON.parse(text) as unknown),
  }
}

/** Sends each test request as a real `Request` through a fetch handler. */
export function fetchTransport(handler: (req: Request) => Promise<Response | null>): Transport {
  return async (outgoing) => {
    const response = await handler(webRequest(outgoing))
    if (response === null) return { status: 0, headers: new Headers(), text: "", json: undefined }
    return replyOfResponse(response)
  }
}

/** A request body that arrives in `count` chunks of `size` bytes, counting how many were pulled. */
export function chunkedBody(count: number, size: number) {
  let pulled = 0
  let cancelled = false
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (pulled === count) {
          controller.close()
          return
        }
        pulled += 1
        controller.enqueue(new Uint8Array(size).fill(0x78))
      },
      cancel() {
        cancelled = true
      },
    },
    { highWaterMark: 0 },
  )
  return { stream, pulled: () => pulled, cancelled: () => cancelled }
}

/** A streamed JSON POST to `path` with the given body stream and no Content-Length. */
export function streamedRequest(path: string, stream: ReadableStream<Uint8Array>): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: ORIGIN },
    body: stream,
    duplex: "half",
  } as RequestInit)
}
