import { createCsrfMiddleware, createMiddleware, createStart } from "@tanstack/react-start"
import { authMiddlewareServer } from "./auth.server"

// test-cap runs first for every request: pages, server routes and server function calls.
const authMiddleware = createMiddleware().server(authMiddlewareServer)

// TanStack Start's own Origin check for server function calls; test-cap checks its /auth/* routes itself.
const csrfMiddleware = createCsrfMiddleware({ filter: (ctx) => ctx.handlerType === "serverFn" })

export const startInstance = createStart(() => ({
  requestMiddleware: [authMiddleware, csrfMiddleware],
}))
