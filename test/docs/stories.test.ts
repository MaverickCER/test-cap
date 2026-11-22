// Storybook shows every default page in every state (owner request, ADR 0025). The stories are generated from
// stories/states.ts; this test fails when a form or a state is missing from a story file, or a state does not show
// what its name says.
import { readFileSync } from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"
import { renderPage } from "../../src/pages/render.js"
import { FORMS, pageStory, STATES, type PageState } from "../../stories/states.js"

const root = path.resolve(import.meta.dirname, "../..")
const EXPORTS: Readonly<Record<PageState, string>> = {
  empty: "Empty",
  "field-error": "FieldError",
  "global-error": "GlobalError",
  busy: "Busy",
  "rate-limited": "RateLimited",
}

describe("Storybook covers every page in every state", () => {
  it.each(FORMS)("stories/%s.stories.ts exports one story per state, in order", (form) => {
    const text = readFileSync(path.join(root, "stories", `${form}.stories.ts`), "utf8")
    const found = [
      ...text.matchAll(/^export const (\w+) = story\("([\w-]+)", "([\w-]+)"\)$/gm),
    ].map((match) => [match[1], match[2], match[3]])
    expect(found).toStrictEqual(STATES.map((state) => [EXPORTS[state], form, state]))
  })

  it.each(FORMS)("%s: each state shows what its name says", (form) => {
    const empty = pageStory(form, "empty")
    expect(empty.model.globalError).toBeNull()
    expect(empty.model.fields.every((field) => field.error === null)).toBe(true)

    const fieldError = pageStory(form, "field-error")
    expect(fieldError.model.fields.some((field) => field.error !== null)).toBe(true)

    const global = pageStory(form, "global-error")
    expect(global.model.globalError).not.toBeNull()
    expect(global.model.fields.every((field) => field.error === null)).toBe(true)

    const busy = pageStory(form, "busy")
    expect([busy.busy, busy.model.globalError]).toStrictEqual([true, null])
    expect(STATES.filter((state) => pageStory(form, state).busy)).toStrictEqual(["busy"])

    expect(pageStory(form, "rate-limited").model.globalError).toBe(
      "Too many attempts. Try again in 30 seconds.",
    )
  })

  it.each(FORMS)("%s renders in every state", (form) => {
    for (const state of STATES) {
      const { model, context } = pageStory(form, state)
      expect(renderPage(model, context)).toContain(`data-form="${form}"`)
    }
  })
})
