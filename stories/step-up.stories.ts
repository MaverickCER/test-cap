import { story } from "./render.js"

export default { title: "Pages/Step-up" }

export const Empty = story("step-up", "empty")
export const FieldError = story("step-up", "field-error")
export const GlobalError = story("step-up", "global-error")
export const Busy = story("step-up", "busy")
export const RateLimited = story("step-up", "rate-limited")
