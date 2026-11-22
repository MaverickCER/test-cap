/**
 * The few browser APIs the stories use, typed here. tsconfig.json keeps the DOM lib out of the whole program so that
 * src cannot come to depend on it, and the stories compile in that same program.
 */

/** An element, as much of one as the stories touch. */
export interface StoryElement {
  textContent: string | null
  /** A form control's current value; absent on other elements. */
  value?: string
  getAttribute(name: string): string | null
  querySelectorAll(selector: string): Iterable<StoryElement>
  append(...nodes: StoryElement[]): void
  querySelector(selector: string): StoryElement | null
  setAttribute(name: string, value: string): void
}

/** A `<style>` element. */
interface StoryStyle extends StoryElement {
  disabled: boolean
}

/** A document: the page's own, or one parsed from markup. */
interface StoryDocument {
  readonly head: StoryElement
  createElement(tag: "script"): StoryElement
  createElement(tag: "style"): StoryStyle
  importNode(node: StoryElement, deep: true): StoryElement
  querySelector(selector: string): StoryElement | null
}

/** The globals the stories read. */
interface Browser {
  readonly document: StoryDocument
  readonly DOMParser: new () => {
    parseFromString(markup: string, type: "text/html"): StoryDocument
  }
}

/** The browser's globals, through the types above. */
export const browser = globalThis as unknown as Browser
