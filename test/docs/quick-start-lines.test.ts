// ADR 0024 §5: the README quick start runs, and a test counts its lines and fails at 20 or more.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import type { RequestListener } from "node:http"
import { tmpdir } from "node:os"
import path from "node:path"
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest"
import { body, Browser, ENV, enrol, hibpClear } from "../support/auth.js"
import { listen } from "../support/http.js"
import { fixedClock } from "../../src/core/clock.js"
import type { EmailMessage } from "../../src/core/auth.js"

const root = path.resolve(import.meta.dirname, "../..")
const readme = readFileSync(path.join(root, "README.md"), "utf8")
const block =
  /<!-- quick-start:begin -->\s*```js\n([\s\S]*?)```\s*<!-- quick-start:end -->/.exec(
    readme,
  )?.[1] ?? ""
const lines = block.trimEnd().split("\n")

/** The block with the package imports pointed at the source and the listen call turned into an export. */
function runnable(): string {
  const sources: Record<string, string> = {
    "test-cap": "src/index.ts",
    "test-cap/express": "src/adapters/express/index.ts",
    "test-cap/store/memory": "src/store/memory.ts",
  }
  let text = block
  for (const [specifier, file] of Object.entries(sources)) {
    text = text.replace(`from "${specifier}"`, `from ${JSON.stringify(path.join(root, file))}`)
  }
  expect(text).toContain("app.listen(3000)")
  return text.replace("app.listen(3000)", "export default app")
}

describe("the README quick start", () => {
  it("is under 20 lines", () => {
    expect(lines.length).toBeGreaterThan(5)
    expect(lines.length).toBeLessThan(20)
  })

  describe("running", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "test-cap-quick-start-"))
    let server: Awaited<ReturnType<typeof listen>>
    /** What the quick start's `sendEmail` printed: each email, as `console.log` received it. */
    const printed: EmailMessage[] = []

    beforeAll(async () => {
      for (const [name, value] of Object.entries(ENV)) vi.stubEnv(name, value)
      // The quick start hands test-cap the global fetch; here it answers HIBP's range query without the network.
      vi.stubGlobal("fetch", hibpClear)
      vi.spyOn(console, "log").mockImplementation((message: EmailMessage) => {
        printed.push(message)
      })
      const file = path.join(directory, "app.mjs")
      writeFileSync(file, runnable())
      const { default: app } = (await import(file)) as { default: RequestListener }
      server = await listen(app)
    })

    afterAll(async () => {
      await server.close()
      vi.unstubAllEnvs()
      vi.unstubAllGlobals()
      vi.restoreAllMocks()
      rmSync(directory, { recursive: true, force: true })
    })

    it("serves the public page and protects the rest", async () => {
      const browser = new Browser(server.transport)
      expect((await browser.get("/")).text).toBe("Welcome")
      expect((await browser.get("/account")).status).toBe(401)
    })

    it("signs a person up to AAL2 and then opens /account", async () => {
      const browser = new Browser(server.transport)
      // The quick start uses the system clock; codes are computed for the moment they are sent.
      const { subject } = await enrol(browser, fixedClock(Date.now()), printed)
      expect(body(await browser.get("/account"))).toEqual({ subject })
    })
  })
})
