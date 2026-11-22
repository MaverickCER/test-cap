/**
 * The parts of jsdom the page tests use. Declared here instead of installing `@types/jsdom`, because those types
 * reference TypeScript's DOM library, which retypes `crypto` and `Uint8Array` for the whole program and breaks
 * `src/`, which runs on Node, Bun and Deno without a DOM.
 */
declare module "jsdom" {
  /** An attribute as `Element.attributes` lists it. */
  export interface TestAttribute {
    readonly name: string
    readonly value: string
  }

  /** A jsdom element, as far as the tests read and drive it. */
  export interface TestElement {
    readonly tagName: string
    readonly id: string
    readonly textContent: string | null
    readonly nextElementSibling: TestElement | null
    readonly attributes: Iterable<TestAttribute>
    readonly method: string
    value: string
    type: string
    getAttribute(name: string): string | null
    hasAttribute(name: string): boolean
    setAttribute(name: string, value: string): void
    querySelector<T extends TestElement = TestElement>(selector: string): T | null
    querySelectorAll<T extends TestElement = TestElement>(
      selector: string,
    ): Iterable<T> & ArrayLike<T>
    focus(): void
    click(): void
    dispatchEvent(event: TestEvent): boolean
  }

  /** A jsdom document. */
  export interface TestDocument extends TestElement {
    readonly title: string
    readonly documentElement: TestElement & { readonly lang: string }
    readonly body: TestElement
    readonly activeElement: TestElement | null
    getElementById(id: string): TestElement | null
  }

  /** A dispatched event. */
  export interface TestEvent {
    readonly defaultPrevented: boolean
  }

  /** The event options the tests pass. */
  export interface TestEventInit {
    readonly bubbles?: boolean
    readonly cancelable?: boolean
  }

  /** A jsdom window. */
  export interface TestWindow {
    readonly document: TestDocument
    readonly Event: new (type: string, init?: TestEventInit) => TestEvent
    readonly FocusEvent: new (type: string, init?: TestEventInit) => TestEvent
    readonly PageTransitionEvent: new (
      type: string,
      init?: TestEventInit & { readonly persisted?: boolean },
    ) => TestEvent
    dispatchEvent(event: TestEvent): boolean
    eval(source: string): unknown
  }

  /** A jsdom instance. */
  export class JSDOM {
    constructor(html: string, options?: { readonly runScripts?: "outside-only" })
    readonly window: TestWindow
  }
}
