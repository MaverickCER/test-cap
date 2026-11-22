// Early redirects only: a visitor with no session cookie is sent home before /billing renders. This is not the
// protection. Next.js's own guide says a proxy "should not be your only line of defense in protecting your data";
// /billing checks the session itself, through server/billing.ts.
import { nextProxy } from "test-cap/next"
import { auth } from "./server/auth"

export const proxy = nextProxy(auth, { public: ["/"], signIn: "/" })

export const config = { matcher: ["/billing/:path*"] }
