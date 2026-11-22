/**
 * Every default page in every state, as data: the stories render these, and test/docs/stories.test.ts checks that each
 * form has each state, so a new form or state cannot be left out of Storybook.
 */
import {
  createForm,
  validateForm,
  withOutcome,
  type FlowOutcome,
  type FormId,
  type FormModel,
} from "../src/forms/model.js"
import type { PageContext } from "../src/pages/render.js"

/** The states a page can be in. `busy` is the client's own state after a valid submit. */
export const STATES = ["empty", "field-error", "global-error", "busy", "rate-limited"] as const

/** One state. */
export type PageState = (typeof STATES)[number]

/** Every form the default pages render. */
export const FORMS: readonly FormId[] = [
  "sign-in",
  "sign-up",
  "email-confirm",
  "password",
  "mfa",
  "totp-enrol",
  "step-up",
]

/** One page in one state: the model and context to render, and whether the client marks it busy. */
export interface PageStory {
  readonly model: FormModel
  readonly context: PageContext
  readonly busy: boolean
}

/** Where each form posts: the dispatcher's route. */
const ACTIONS: Readonly<Record<FormId, string>> = {
  "sign-in": "/auth/sign-in",
  "sign-up": "/auth/sign-up",
  "email-confirm": "/auth/email/confirm",
  password: "/auth/password",
  mfa: "/auth/totp/verify",
  "totp-enrol": "/auth/totp/confirm",
  "step-up": "/auth/step-up",
}

/** The refusal each form's flow gives for a valid-looking submission. */
const REFUSALS: Readonly<Record<FormId, FlowOutcome["error"]>> = {
  "sign-in": "invalid-credentials",
  "sign-up": "unexpected",
  "email-confirm": "invalid-code",
  password: "too-common",
  mfa: "invalid-code",
  "totp-enrol": "invalid-code",
  "step-up": "invalid-code",
}

/** What a person typed before a valid submit; the busy state shows it, as the browser still would. */
export const SUBMITTED: Readonly<Record<string, string>> = {
  identifier: "ada@example.com",
  password: "correct horse battery staple",
  code: "123456",
}
const INVALID = { identifier: "ada", password: "", code: "12" }

function context(form: FormId): PageContext {
  return {
    action: ACTIONS[form],
    csrfToken: "story-token",
    assets: {
      script: "/auth/assets/test-cap.000000000000.js",
      style: "/auth/assets/test-cap.000000000000.css",
    },
    totpSecret: form === "totp-enrol" ? "JBSWY3DPEHPK3PXP" : undefined,
    hidden:
      form === "totp-enrol"
        ? { authenticatorId: "YXV0aGVudGljYXRvcg" }
        : form === "step-up"
          ? { challenge: "Y2hhbGxlbmdl" }
          : undefined,
    links:
      form === "sign-in"
        ? [{ href: "/auth/sign-up", text: "Create an account" }]
        : form === "sign-up"
          ? [{ href: "/auth/sign-in", text: "I already have an account" }]
          : undefined,
    resend: form === "email-confirm" ? "/auth/email/resend" : undefined,
  }
}

/** The model and context for `form` in `state`. */
export function pageStory(form: FormId, state: PageState): PageStory {
  const empty = createForm(form)
  const models: Readonly<Record<PageState, () => FormModel>> = {
    empty: () => empty,
    "field-error": () => validateForm(empty, INVALID),
    "global-error": () => withOutcome(validateForm(empty, SUBMITTED), { error: REFUSALS[form] }),
    busy: () => validateForm(empty, SUBMITTED),
    "rate-limited": () =>
      withOutcome(validateForm(empty, SUBMITTED), { error: "rate-limited", retryAfterMs: 30_000 }),
  }
  return { model: models[state](), context: context(form), busy: state === "busy" }
}
