import { createServerFn } from "@tanstack/react-start"
import { getRequest } from "@tanstack/react-start/server"
import { authRoutes } from "./auth.server"

/**
 * The account page's data. `/account` is on the middleware's public list, so nothing ran before this: the function
 * checks `account.view` (AAL1, a password alone) itself and answers with the outcome. An `enroll` or `recovery-only`
 * session is refused here as everywhere.
 */
export const getAccount = createServerFn({ method: "GET" }).handler(async () => {
  const result = await authRoutes.require(getRequest(), "account.view")
  if (result.outcome !== "allow") return { outcome: result.outcome, subject: null, level: null }
  return { outcome: result.outcome, subject: result.subject, level: result.assurance.level }
})
