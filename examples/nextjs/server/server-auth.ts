// The authoritative check: every route handler, server function and data-access function that needs a session
// calls it.
import { headers } from "next/headers"
import { nextServerAuth } from "test-cap/next"
import { auth } from "./auth"

export const serverAuth = nextServerAuth(auth, { headers })
