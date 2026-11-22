// Gzip size budgets, read by `internal-package-contract tool size` (the `Size` check), which gzips each budget's
// `file` and compares it with `maxGzipBytes`.
//
// Each `exports` entry is measured with every chunk it imports: an entry file such as dist/index.js only re-exports
// from shared chunks, so its own bytes say nothing about what an app loads. Loading this module writes, for each
// entry, the entry and the dist/ chunks it reaches through relative imports, concatenated, to
// node_modules/.cache/size-budgets/, and that file is what the Size check gzips. Libraries an entry imports by package
// name (hash-wasm) are dependencies, not part of the entry, and are left out, as ADR 0018 says.
//
// Budgets (ADR 0018 Open 4):
// - Server entries: the first measurement plus 10 percent, rounded up. Measured on 2026-11-16 from the phase 3 build.
// - The default pages' hashed assets (the script and the stylesheet a browser downloads): 15 KiB in total, ADR 0018's
//   fixed budget for client-facing code. They are read from a running `auth.handle` built from dist/, exactly as a
//   browser gets them, and gzipped as one stream, which can come out up to a few hundred bytes smaller than the two
//   files gzipped one by one.
// A new `exports` entry adds a line here in the same pull request; test/budgets/size-budgets.test.ts fails until it does.
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import path from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
/** Generated, never committed and never linted: next to the other tool caches under node_modules. */
const out = path.join(root, "node_modules", ".cache", "size-budgets")

/** The first measured gzip size of each server entry with its chunks, in bytes. */
export const MEASURED = {
  core: 35_898,
  "express adapter": 36_689,
  "fetch adapter": 36_774,
  "next adapter": 37_261,
  "tanstack-start adapter": 36_855,
  "memory store": 2_222,
}

/** The first measurement plus 10 percent, rounded up to a whole byte. */
export const plusTenPercent = (bytes) => Math.ceil(bytes * 1.1)

/** Each relative import of a built ES module: `from "./x.js"`, `import "./x.js"`, `import("./x.js")`. */
const RELATIVE = /(?:\bfrom\s*|\bimport\s*\(?\s*)["'](\.{1,2}\/[^"']+)["']/g

/** The file and every dist/ file it reaches through relative imports, each once, the entry first. */
export function closure(file) {
  const seen = []
  const visit = (current) => {
    if (seen.includes(current)) return
    seen.push(current)
    for (const [, specifier] of readFileSync(current, "utf8").matchAll(RELATIVE)) {
      visit(path.resolve(path.dirname(current), specifier))
    }
  }
  visit(file)
  return seen
}

/** Writes the entry with its chunks to <out>/<name>.js; removes a stale one when dist/ has no such entry. */
function bundle(entry, name) {
  const target = path.join(out, `${name}.js`)
  const source = path.join(root, entry)
  if (!existsSync(source)) {
    rmSync(target, { force: true })
  } else {
    mkdirSync(out, { recursive: true })
    writeFileSync(
      target,
      closure(source)
        .map((file) => readFileSync(file, "utf8"))
        .join("\n"),
    )
  }
  return path.relative(root, target)
}

/** The script and stylesheet a default page links to, fetched from an `auth.handle` built from dist/. */
async function pageAssetsFile() {
  const target = path.join(out, "page-assets.txt")
  rmSync(target, { force: true })
  const index = path.join(root, "dist/index.js")
  const memory = path.join(root, "dist/store/memory.js")
  if (!existsSync(index) || !existsSync(memory)) return path.relative(root, target)
  const { createAuth } = await import(pathToFileURL(index).href)
  const { memoryStore } = await import(pathToFileURL(memory).href)
  const auth = createAuth({
    store: memoryStore(),
    env: { APP_ENV: "test", APP_ORIGIN: "http://localhost:3000", APP_SYSTEM_ID: "size-budgets" },
    hibpFetch: () => Promise.reject(new Error("no network")),
    sendEmail: () => Promise.resolve(),
  })
  const get = (url) => auth.handle({ method: "GET", url, headers: new Headers(), body: null })
  const page = new TextDecoder().decode((await get("/auth/sign-in")).body)
  const paths = [...page.matchAll(/(?:src|href)="(\/auth\/assets\/[^"]+)"/g)].map(
    (match) => match[1],
  )
  const bodies = await Promise.all(paths.map(async (asset) => (await get(asset)).body))
  mkdirSync(out, { recursive: true })
  writeFileSync(target, Buffer.concat(bodies))
  return path.relative(root, target)
}

const server = (label, entry, name) => ({
  label,
  entry,
  file: bundle(entry, name),
  maxGzipBytes: plusTenPercent(MEASURED[label]),
})

export default [
  server("core", "dist/index.js", "core"),
  server("express adapter", "dist/express.js", "express"),
  server("fetch adapter", "dist/fetch.js", "fetch"),
  server("next adapter", "dist/next.js", "next"),
  server("tanstack-start adapter", "dist/tanstack-start.js", "tanstack-start"),
  server("memory store", "dist/store/memory.js", "memory"),
  { label: "default page assets", file: await pageAssetsFile(), maxGzipBytes: 15 * 1024 },
]
