import { story } from "./render.js"

export default { title: "Pages/Sign up" }

export const Empty = story("sign-up", "empty")
export const FieldError = story("sign-up", "field-error")
export const GlobalError = story("sign-up", "global-error")
export const Busy = story("sign-up", "busy")
export const RateLimited = story("sign-up", "rate-limited")
