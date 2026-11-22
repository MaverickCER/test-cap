import { createServer, request as httpRequest, type RequestListener } from "node:http"
import type { AddressInfo } from "node:net"
import type { Reply, Transport } from "./auth.js"

/** Serves `app` (an Express app or any request listener) on an ephemeral loopback port. */
export async function listen(app: RequestListener) {
  const server = createServer(app)
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  const { port } = server.address() as AddressInfo
  return {
    port,
    transport: httpTransport(port),
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections()
        server.close((error) => (error ? reject(error) : resolve()))
      }),
  }
}

/** Sends each request to 127.0.0.1:`port` over a real socket, the path exactly as given and every header line as given. */
export function httpTransport(port: number): Transport {
  return (outgoing) =>
    new Promise<Reply>((resolve, reject) => {
      const flat = (outgoing.headers ?? []).flatMap(([name, value]) => [name, value])
      const body = outgoing.body
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port,
          method: outgoing.method,
          path: outgoing.path,
          // An array of headers is sent exactly as given, so Host must be in it.
          headers: [
            "Host",
            `127.0.0.1:${port}`,
            ...flat,
            ...(body === undefined ? [] : ["Content-Length", String(Buffer.byteLength(body))]),
          ],
        },
        (res) => {
          const chunks: Buffer[] = []
          res.on("data", (chunk: Buffer) => chunks.push(chunk))
          res.on("end", () => {
            const headers = new Headers()
            for (let i = 0; i < res.rawHeaders.length; i += 2) {
              headers.append(res.rawHeaders[i] ?? "", res.rawHeaders[i + 1] ?? "")
            }
            const text = Buffer.concat(chunks).toString("utf8")
            let json: unknown
            try {
              json = text === "" ? undefined : JSON.parse(text)
            } catch {
              json = undefined
            }
            resolve({ status: res.statusCode ?? 0, headers, text, json })
          })
        },
      )
      req.on("error", reject)
      req.end(body)
    })
}
