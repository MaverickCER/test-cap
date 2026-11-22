/** Turns a page story into the element Storybook shows, and runs the page's own client script on it. */
import type { FormId } from "../src/forms/model.js"
import { CLIENT_SCRIPT } from "../src/pages/assets.js"
import { renderPage } from "../src/pages/render.js"
import { browser, type StoryElement } from "./dom.js"
import { pageStory, SUBMITTED, type PageState } from "./states.js"

/** The page's `<main>`, parsed from the full document `renderPage` returns. */
function render(form: FormId, state: PageState): StoryElement {
  const story = pageStory(form, state)
  const page = new browser.DOMParser().parseFromString(
    renderPage(story.model, story.context),
    "text/html",
  )
  const main = page.querySelector("main")
  if (main === null) throw new Error("renderPage returned no <main>.")
  return browser.document.importNode(main, true)
}

/** Runs the shipped client script, as a page load would, then sets what it sets during a submit. */
function enhance(canvas: StoryElement, busy: boolean): void {
  const script = browser.document.createElement("script")
  script.textContent = CLIENT_SCRIPT
  canvas.append(script)
  if (!busy) return
  for (const input of canvas.querySelectorAll('[data-test-cap="input"]')) {
    input.value = SUBMITTED[input.getAttribute("name") ?? ""] ?? ""
  }
  const form = canvas.querySelector('form[data-test-cap="form"]')
  form?.setAttribute("aria-busy", "true")
  form?.querySelector('[data-test-cap="submit"]')?.setAttribute("aria-disabled", "true")
}

/** One story: the page for `form` in `state`. */
export function story(form: FormId, state: PageState) {
  return {
    name: state.replace("-", " "),
    render: () => render(form, state),
    play: ({ canvasElement }: { canvasElement: StoryElement }) => {
      enhance(canvasElement, state === "busy")
    },
  }
}
