// Every test-cap route: /auth/session, /auth/sign-up, /auth/sign-in, /auth/totp/verify, /auth/sign-out and the rest.
import { nextAuthHandler } from "test-cap/next"
import { auth } from "../../../server/auth"

export const { GET, POST } = nextAuthHandler(auth)
