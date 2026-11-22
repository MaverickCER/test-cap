import { story } from "./render.js"

export default { title: "Pages/Choose a password" }

export const Empty = story("password", "empty")
export const FieldError = story("password", "field-error")
export const GlobalError = story("password", "global-error")
export const Busy = story("password", "busy")
export const RateLimited = story("password", "rate-limited")
