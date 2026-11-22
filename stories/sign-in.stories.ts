import { story } from "./render.js"

export default { title: "Pages/Sign in" }

export const Empty = story("sign-in", "empty")
export const FieldError = story("sign-in", "field-error")
export const GlobalError = story("sign-in", "global-error")
export const Busy = story("sign-in", "busy")
export const RateLimited = story("sign-in", "rate-limited")
