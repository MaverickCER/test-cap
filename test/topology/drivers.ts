// One request path per adapter, so every topology scenario runs through each the same way. The socket peer every
// driver reports is 127.0.0.1: Express gets it from a real loopback socket, the Web-Request adapters from their
// `clientAddress` option. A scenario makes that peer a trusted proxy, an untrusted one, or the client itself, through
// the configuration alone. The Nest leg lives in the Nest adapter's own suite on the same scenarios.
import express from "express"
import { expressAuth } from "../../src/adapters/express/index.js"
import { fetchAuth } from "../../src/adapters/fetch/index.js"
import { nextAuthHandler } from "../../src/adapters/next/index.js"
import { tanstackStartAuth } from "../../src/adapters/tanstack-start/index.js"
import type { Auth } from "../../src/core/auth.js"
import { ORIGIN, type Outgoing, type Reply, type Transport } from "../support/auth.js"
import { listen } from "../support/http.js"

export const PEER = "127.0.0.1"

const decoder = new TextDecoder()

/** A test request as the Web `Request` a server hands a Web-Request adapter. */
function requestOf(outgoing: Outgoing): Request {
  const body = outgoing.body
  return new Request(`${ORIGIN}${outgoing.path}`, {
    method: outgoing.method,
    headers: (outgoing.headers ?? []).map(([name, value]) => [name, value]),
    body: body === undefined ? null : typeof body === "string" ? body : new Uint8Array(body),
  })
}

async function replyOf(response: Response | null | undefined): Promise<Reply> {
  if (response === null || response === undefined) {
    return { status: 0, headers: new Headers(), text: "", json: undefined }
  }
  const text = decoder.decode(await response.arrayBuffer())
  let json: unknown
  try {
    json = text === "" ? undefined : JSON.parse(text)
  } catch {
    json = undefined
  }
  return { status: response.status, headers: response.headers, text, json }
}

/** An adapter under test: a transport for one `Auth`, and how to release it. */
export interface Driver {
  readonly name: string
  /** True when the adapter can report a socket peer; Next.js and TanStack Start report one only through an option. */
  open(
    auth: Auth<string>,
    peer: string | undefined,
  ): Promise<{ transport: Transport; close(): Promise<void> }>
}

const none = (): Promise<void> => Promise.resolve()

export const DRIVERS: readonly Driver[] = [
  {
    name: "express",
    async open(auth) {
      const app = express()
      app.use(expressAuth(auth, { public: ["/"] }))
      const server = await listen(app)
      return { transport: server.transport, close: server.close }
    },
  },
  {
    name: "fetch",
    open(auth, peer) {
      const serve = fetchAuth(auth, { clientAddress: () => peer })
      return Promise.resolve({
        transport: async (outgoing) => replyOf(await serve(requestOf(outgoing))),
        close: none,
      })
    },
  },
  {
    name: "next",
    open(auth, peer) {
      const { GET, POST } = nextAuthHandler(auth, {
        clientAddress: peer === undefined ? undefined : () => peer,
      })
      return Promise.resolve({
        transport: async (outgoing) =>
          replyOf(await (outgoing.method === "GET" ? GET : POST)(requestOf(outgoing))),
        close: none,
      })
    },
  },
  {
    name: "tanstack-start",
    open(auth, peer) {
      const { handlers } = tanstackStartAuth(auth, {
        clientAddress: peer === undefined ? undefined : () => peer,
      })
      return Promise.resolve({
        transport: async (outgoing) =>
          replyOf(await handlers.ANY({ request: requestOf(outgoing) })),
        close: none,
      })
    },
  },
]
