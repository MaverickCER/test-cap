// The data-access layer for billing: it checks the session itself, next to the data, so no caller can skip it.
import { serverAuth } from "./server-auth"

export type Billing =
  | { readonly kind: "allowed"; readonly subject: string; readonly invoices: readonly string[] }
  | { readonly kind: "denied"; readonly outcome: string }

export async function billing(): Promise<Billing> {
  const result = await serverAuth.require()
  if (result.outcome !== "allow") return { kind: "denied", outcome: result.outcome }
  return { kind: "allowed", subject: result.subject, invoices: ["INV-0001", "INV-0002"] }
}
