import { story } from "./render.js"

export default { title: "Pages/TOTP enrolment" }

export const Empty = story("totp-enrol", "empty")
export const FieldError = story("totp-enrol", "field-error")
export const GlobalError = story("totp-enrol", "global-error")
export const Busy = story("totp-enrol", "busy")
export const RateLimited = story("totp-enrol", "rate-limited")
