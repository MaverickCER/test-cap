import { createServerFn } from "@tanstack/react-start"
import { getRequest } from "@tanstack/react-start/server"
import { authRoutes } from "./auth.server"

/** The billing page's data. The middleware already required AAL2; the session names who is signed in. */
export const getBilling = createServerFn({ method: "GET" }).handler(async () => {
  const session = await authRoutes.session(getRequest())
  return { subject: session?.subject ?? null, level: session?.level ?? null }
})

/** Needs `billing.export`: the server function checks it itself and answers with the outcome. */
export const exportInvoices = createServerFn({ method: "GET" }).handler(async () => {
  const result = await authRoutes.require(getRequest(), "billing.export")
  if (result.outcome !== "allow") return { outcome: result.outcome, invoices: [] }
  return { outcome: result.outcome, invoices: ["inv-2026-001", "inv-2026-002"] }
})

/** Needs `billing.close` (AAL3), which a password and TOTP session never meets: the answer says what is missing. */
export const closeAccount = createServerFn({ method: "POST" }).handler(async () => {
  const result = await authRoutes.require(getRequest(), "billing.close")
  if (result.outcome !== "allow") return { outcome: result.outcome, closed: false }
  return { outcome: result.outcome, closed: true }
})
