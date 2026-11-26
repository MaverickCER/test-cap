// The data-access layer for the account: it checks the session itself, next to the data, so no caller can skip it.
// It names `account.view`, which needs only a signed-in session (AAL1); billing names no requirement and gets AAL2.
import type { AssuranceLevel } from "test-cap"
import { serverAuth } from "./server-auth"

export type Account =
  | {
      readonly kind: "allowed"
      readonly subject: string
      readonly level: AssuranceLevel | null
    }
  | { readonly kind: "denied"; readonly outcome: string }

export async function account(): Promise<Account> {
  const result = await serverAuth.require("account.view")
  // `enroll` (no second factor set up yet) and `recovery-only` are refused here as everywhere: a session in those
  // states reaches nothing, whatever the level asked for.
  if (result.outcome !== "allow") return { kind: "denied", outcome: result.outcome }
  return { kind: "allowed", subject: result.subject, level: result.assurance.level }
}
