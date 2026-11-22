// Plumbing for the example e2e tests. It imports only types from src/: an example test drives the packed package over
// HTTP, so it must not depend on the source tree, and mutation testing (which reruns the tests related to a mutated
// source file) never picks it up.
import { type ChildProcess, spawn, spawnSync } from "node:child_process"
import { createHmac } from "node:crypto"
import { existsSync, readFileSync } from "node:fs"
import { createServer, request as httpRequest } from "node:http"
import type { AddressInfo } from "node:net"
import path from "node:path"
import type { EmailMessage } from "../../src/core/auth.js"
import type { Reply, Transport } from "../support/auth.js"
import { httpTransport as loopbackTransport } from "../support/http.js"

/** The password the journeys use: it passes test-cap's length, blocklist and context checks. */
export const PASSWORD = "correct horse battery staple"

/** A browser on an app: keeps cookies and the synchronizer token, and sends the app's origin on every POST. */
export class Client {
  readonly cookies = new Map<string, string>()
  private csrf: string | null = null
  private readonly transport: ReturnType<typeof loopbackTransport>

  constructor(
    port: number,
    private readonly origin: string,
  ) {
    this.transport = loopbackTransport(port)
  }

  private async send(
    method: string,
    path: string,
    headers: [string, string][],
    body?: string,
  ): Promise<Reply> {
    const jar = [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ")
    const reply = await this.transport({
      method,
      path,
      headers: [...(jar === "" ? [] : [["Cookie", jar] as [string, string]]), ...headers],
      body,
    })
    for (const line of reply.headers.getSetCookie()) {
      const [pair = ""] = line.split(";")
      const equals = pair.indexOf("=")
      const name = pair.slice(0, equals)
      if (/;\s*Max-Age=0(?:;|$)/i.test(line)) this.cookies.delete(name)
      else this.cookies.set(name, pair.slice(equals + 1))
    }
    const issued = reply.headers.get("x-csrf-token")
    if (issued !== null) this.csrf = issued
    return reply
  }

  /** A GET with the jar. */
  get(path: string): Promise<Reply> {
    return this.send("GET", path, [])
  }

  /** Fetches a synchronizer token from the session endpoint. */
  async start(): Promise<Reply> {
    const reply = await this.get("/auth/session")
    this.csrf = (reply.json as { csrfToken: string }).csrfToken
    return reply
  }

  /** A same-origin JSON POST carrying the synchronizer token. */
  post(path: string, body: Record<string, unknown> = {}): Promise<Reply> {
    return this.send(
      "POST",
      path,
      [
        ["Origin", this.origin],
        ["Content-Type", "application/json"],
        ...(this.csrf === null ? [] : [["X-CSRF-Token", this.csrf] as [string, string]]),
      ],
      JSON.stringify(body),
    )
  }
}

/** RFC 4648 base32, as authenticator apps read a TOTP secret. */
function base32(secret: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let bits = ""
  for (const char of secret.replace(/=+$/, "")) {
    bits += alphabet.indexOf(char.toUpperCase()).toString(2).padStart(5, "0")
  }
  const bytes = bits.match(/.{8}/g) ?? []
  return Buffer.from(bytes.map((byte) => Number.parseInt(byte, 2)))
}

/** The RFC 6238 code (SHA-1, 30-second steps, 6 digits) of a base32 secret at `ms`, as an authenticator app shows it. */
export function totpCode(secret: string, ms: number): string {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(ms / 30_000)))
  const mac = createHmac("sha1", base32(secret)).update(counter).digest()
  const offset = (mac[mac.length - 1] as number) & 0x0f
  const value = mac.readUInt32BE(offset) & 0x7fffffff
  return String(value % 1_000_000).padStart(6, "0")
}

/**
 * Shared plumbing for `test/examples/<name>.test.ts`. Each example is its own npm project that installs this package
 * from the tarball `npm pack` makes, as an app would. CI's `examples` job packs, installs and runs them; the root
 * install does not, so every example test skips when the example has no `node_modules`.
 */

const repositoryRoot = path.resolve(import.meta.dirname, "../..")
const examplesRoot = path.join(repositoryRoot, "examples")

/** True when the example's own dependencies are installed. */
export function isInstalled(example: string): boolean {
  return existsSync(path.join(examplesRoot, example, "node_modules"))
}

/** Runs an npm script in the example; fails with its output when it exits non-zero. */
export function runScript(example: string, script: string): string {
  const result = spawnSync("npm", ["run", "--silent", script], {
    cwd: path.join(examplesRoot, example),
    encoding: "utf8",
  })
  const output = `${result.stdout}${result.stderr}`
  if (result.status !== 0) {
    throw new Error(
      `"npm run ${script}" in examples/${example} exited ${String(result.status)}.\n${output}`,
    )
  }
  return output
}

/**
 * True when the example installed the package this tree builds: the installed entry is byte for byte the one in
 * `dist/`. A tarball packed before the last build, or an install from an npm cache, fails here.
 */
export function installedMatchesBuild(example: string, distFile: string): boolean {
  const installed = path.join(examplesRoot, example, "node_modules/test-cap/dist", distFile)
  const built = path.join(repositoryRoot, "dist", distFile)
  return readFileSync(installed).equals(readFileSync(built))
}

/** A started example: its port, the emails it has sent so far, and how to stop it. */
export interface Started {
  readonly port: number
  /** Every message the example printed as an `outbox` line, oldest first. */
  outbox(): readonly EmailMessage[]
  stop(): Promise<void>
}

/**
 * Starts the example's server with `env`, and resolves once it prints `listening on <url>`. Each `outbox <json>` line
 * it prints afterwards is an email it was asked to send.
 */
export function start(example: string, env: Readonly<Record<string, string>>): Promise<Started> {
  const child: ChildProcess = spawn("node", ["server.mjs"], {
    cwd: path.join(examplesRoot, example),
    env: { ...process.env, ...env, PORT: "0", HOST: "127.0.0.1" },
    stdio: ["ignore", "pipe", "pipe"],
  })
  let output = ""
  const outbox = () =>
    output
      .split("\n")
      .filter((line) => line.startsWith("outbox "))
      .map((line) => JSON.parse(line.slice("outbox ".length)) as EmailMessage)
  const stop = () =>
    new Promise<void>((resolve) => {
      if (child.exitCode !== null) resolve()
      else {
        child.once("exit", () => resolve())
        child.kill("SIGTERM")
      }
    })
  return new Promise((resolve, reject) => {
    const read = (chunk: Buffer) => {
      output += chunk.toString("utf8")
      const match = /listening on http:\/\/[^:]+:(\d+)/.exec(output)
      if (match !== null) resolve({ port: Number(match[1]), outbox, stop })
    }
    child.stdout?.on("data", read)
    child.stderr?.on("data", read)
    child.once("exit", (code) => {
      reject(new Error(`examples/${example} exited ${String(code)} before listening.\n${output}`))
    })
  })
}

/**
 * Sends each request over a real socket to `port`, the path exactly as given, with `Host` set to `host`: the app's
 * own origin, which TanStack Start's server function check and test-cap's `APP_ORIGIN` both compare with.
 */
export function httpTransport(port: number, host: string): Transport {
  return (outgoing) =>
    new Promise<Reply>((resolve, reject) => {
      const body = outgoing.body
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port,
          method: outgoing.method,
          path: outgoing.path,
          headers: [
            "Host",
            host,
            ...(outgoing.headers ?? []).flatMap(([name, value]) => [name, value]),
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

/** A local stand-in for the HIBP range API, and the range paths it was asked for. */
export interface HibpStub {
  /** The origin to pass the example as `HIBP_STUB_ORIGIN`. */
  readonly origin: string
  /** Every path it was asked for, such as `/range/5BAA6`, oldest first. */
  readonly requests: readonly string[]
  close(): Promise<void>
}

/**
 * Starts a stand-in for the HIBP range API on a loopback port. It answers every range with a padding row only, so no
 * password is breached, and the example's real breached-password check runs without the network.
 */
export async function hibpStub(): Promise<HibpStub> {
  const requests: string[] = []
  const server = createServer((req, res) => {
    requests.push(req.url ?? "")
    res.writeHead(200, { "Content-Type": "text/plain" })
    res.end("0000000000000000000000000000000000A:0")
  })
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  const { port } = server.address() as AddressInfo
  return {
    origin: `http://127.0.0.1:${port}`,
    requests,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections()
        server.close((error) => (error ? reject(error) : resolve()))
      }),
  }
}
