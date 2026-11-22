import { story } from "./render.js"

export default { title: "Pages/Email confirmation" }

export const Empty = story("email-confirm", "empty")
export const FieldError = story("email-confirm", "field-error")
export const GlobalError = story("email-confirm", "global-error")
export const Busy = story("email-confirm", "busy")
export const RateLimited = story("email-confirm", "rate-limited")
