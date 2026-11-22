// Serves the production build on Node: the built client assets as static files, and everything else through
// TanStack Start, whose global request middleware is test-cap's deny by default.
//
// `vite dev` loads .env itself, as TanStack Start documents. A production server reads its environment from the host
// instead, so this one loads the committed .env with Node's own loader first; a variable the environment already sets
// wins over the file. The app is imported only afterwards, because creating the Auth reads the environment.
import { fileURLToPath } from "node:url"
import { serve } from "srvx"
import { staticMiddleware } from "srvx/static"

process.loadEnvFile(fileURLToPath(new URL(".env", import.meta.url)))
const { default: app } = await import("./dist/server/server.js")

const server = serve({
  fetch: app.fetch,
  // The built JavaScript and CSS only: hashed, public, and never under /auth/.
  middleware: [staticMiddleware({ dir: fileURLToPath(new URL("dist/client", import.meta.url)) })],
  port: process.env.PORT ?? 3000,
  hostname: process.env.HOST ?? "127.0.0.1",
  silent: true,
})
await server.ready()
// The end-to-end test reads this line to learn the port.
console.log(`listening on ${server.url}`)
