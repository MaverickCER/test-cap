import { story } from "./render.js"

export default { title: "Pages/MFA challenge" }

export const Empty = story("mfa", "empty")
export const FieldError = story("mfa", "field-error")
export const GlobalError = story("mfa", "global-error")
export const Busy = story("mfa", "busy")
export const RateLimited = story("mfa", "rate-limited")
