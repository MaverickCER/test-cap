// The optional stylesheet the pages ship, with a toolbar switch: the pages are unstyled by default, for the app's own CSS.
import type { Preview } from "@storybook/html-vite"
import { STYLESHEET } from "../src/pages/assets.js"
import { browser } from "../stories/dom.js"

const style = browser.document.createElement("style")
style.textContent = STYLESHEET
browser.document.head.append(style)

const preview: Preview = {
  globalTypes: {
    stylesheet: {
      description: "The optional test-cap stylesheet",
      toolbar: { title: "Stylesheet", items: ["on", "off"], dynamicTitle: true },
    },
  },
  initialGlobals: { stylesheet: "on" },
  decorators: [
    (renderStory, { globals }) => {
      style.disabled = globals["stylesheet"] === "off"
      return renderStory()
    },
  ],
}

export default preview
