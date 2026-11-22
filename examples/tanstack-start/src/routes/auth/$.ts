import { createFileRoute } from "@tanstack/react-router"
import { authRoutes } from "../../auth.server"

// Every /auth/* route: sign-up, sign-in, TOTP, step-up, sign-out and the session.
export const Route = createFileRoute("/auth/$")({
  server: { handlers: authRoutes.handlers },
})
