/**
 * The default pages' two static assets (ADR 0025 §4): the browser script that adds blur validation, focus, the busy
 * state and the show-password toggle on top of forms that already work without it, and an optional stylesheet. Each
 * is served under a name that carries a hash of its content, so it can be cached as immutable.
 *
 * The script reads every rule and message from the page's data attributes, which the form model wrote, so the browser
 * and the server check the same rules with the same words. It is plain ES2017 with no imports, kept as text so it
 * ships unchanged; the page tests run it in jsdom.
 */

import { hexEncode, sha256, utf8Encode } from "../core/encoding.js"

/** The browser script. */
export const CLIENT_SCRIPT = `(function () {
  "use strict";

  function prepared(input) {
    return input.getAttribute("data-strip") === "whitespace" ? input.value.replace(/\\s/g, "") : input.value;
  }

  function problem(input) {
    var value = prepared(input);
    if (value === "") return input.getAttribute("data-required-message");
    var length = Array.from(value.normalize("NFC")).length;
    var min = input.getAttribute("data-min");
    var max = input.getAttribute("data-max");
    if (min !== null && length < Number(min)) return input.getAttribute("data-too-short-message");
    if (max !== null && length > Number(max)) return input.getAttribute("data-too-long-message");
    var pattern = input.getAttribute("data-pattern");
    if (pattern !== null && !new RegExp("^(?:" + pattern + ")$").test(value)) {
      return input.getAttribute("data-pattern-message");
    }
    return null;
  }

  function show(input) {
    var error = problem(input);
    var note = document.getElementById(input.getAttribute("aria-describedby"));
    if (error === null) {
      input.removeAttribute("aria-invalid");
      note.textContent = input.getAttribute("data-help");
      note.removeAttribute("data-state");
      return true;
    }
    input.setAttribute("aria-invalid", "true");
    note.textContent = error;
    note.setAttribute("data-state", "error");
    return false;
  }

  function idle(form) {
    form.removeAttribute("aria-busy");
    var submit = form.querySelector('[data-test-cap="submit"]');
    if (submit !== null) submit.removeAttribute("aria-disabled");
  }

  function enhance(form) {
    form.setAttribute("novalidate", "");
    var inputs = Array.prototype.slice.call(form.querySelectorAll('[data-test-cap="input"]'));
    inputs.forEach(function (input) {
      input.addEventListener("input", function () {
        input.setAttribute("data-dirty", "");
        if (input.getAttribute("aria-invalid") === "true") show(input);
      });
      input.addEventListener("blur", function () {
        if (input.hasAttribute("data-dirty")) show(input);
      });
    });
    form.addEventListener("submit", function (event) {
      if (form.getAttribute("aria-busy") === "true") {
        event.preventDefault();
        return;
      }
      var first = null;
      inputs.forEach(function (input) {
        if (!show(input) && first === null) first = input;
      });
      if (first !== null) {
        event.preventDefault();
        first.focus();
        return;
      }
      form.setAttribute("aria-busy", "true");
      var submit = form.querySelector('[data-test-cap="submit"]');
      if (submit !== null) submit.setAttribute("aria-disabled", "true");
    });
    window.addEventListener("pageshow", function (event) {
      if (event.persisted) idle(form);
    });
  }

  function toggle(button) {
    var input = document.getElementById(button.getAttribute("aria-controls"));
    button.removeAttribute("hidden");
    button.addEventListener("click", function () {
      var hidden = input.type === "password";
      input.type = hidden ? "text" : "password";
      button.textContent = button.getAttribute(hidden ? "data-hide" : "data-show");
    });
  }

  Array.prototype.forEach.call(document.querySelectorAll('form[data-test-cap="form"]'), enhance);
  Array.prototype.forEach.call(document.querySelectorAll('[data-test-cap="toggle-password"]'), toggle);
})();
`

/** The optional stylesheet: readable defaults, touch-sized targets, and no motion for those who ask for none. */
export const STYLESHEET = `:root {
  --test-cap-font: system-ui, sans-serif;
  --test-cap-text: #1b1b1f;
  --test-cap-muted: #4a4a55;
  --test-cap-surface: #ffffff;
  --test-cap-border: #6b6b78;
  --test-cap-accent: #1f4fd1;
  --test-cap-on-accent: #ffffff;
  --test-cap-error: #b3261e;
  --test-cap-radius: 0.5rem;
}

@media (prefers-color-scheme: dark) {
  :root {
    --test-cap-text: #ececf1;
    --test-cap-muted: #b9b9c6;
    --test-cap-surface: #16161a;
    --test-cap-border: #8a8a99;
    --test-cap-accent: #8fb0ff;
    --test-cap-on-accent: #0b0b0f;
    --test-cap-error: #ffb4ab;
  }
}

body {
  margin: 0;
  background: var(--test-cap-surface);
  color: var(--test-cap-text);
  font-family: var(--test-cap-font);
  line-height: 1.5;
}

[data-test-cap="page"] {
  max-width: 26rem;
  margin: 0 auto;
  padding: 2rem 1rem;
}

[data-test-cap="field"] {
  display: grid;
  gap: 0.25rem;
  margin-bottom: 1rem;
}

[data-test-cap="input"],
[data-test-cap="submit"],
[data-test-cap="toggle-password"] {
  min-height: 2.75rem;
  font: inherit;
  border-radius: var(--test-cap-radius);
}

[data-test-cap="input"] {
  padding: 0 0.75rem;
  border: 1px solid var(--test-cap-border);
  background: var(--test-cap-surface);
  color: var(--test-cap-text);
}

[data-test-cap="input"][aria-invalid="true"] {
  border-color: var(--test-cap-error);
}

[data-test-cap="note"] {
  margin: 0;
  color: var(--test-cap-muted);
  font-size: 0.9375rem;
}

[data-test-cap="note"][data-state="error"],
[data-test-cap="global-error"] {
  color: var(--test-cap-error);
}

[data-test-cap="global-error"]:empty {
  display: none;
}

[data-test-cap="submit"] {
  width: 100%;
  border: 0;
  background: var(--test-cap-accent);
  color: var(--test-cap-on-accent);
  font-weight: 600;
  cursor: pointer;
  transition: opacity 120ms ease-out;
}

[data-test-cap="submit"][aria-disabled="true"] {
  opacity: 0.7;
  cursor: progress;
}

[data-test-cap="toggle-password"] {
  justify-self: start;
  padding: 0 0.75rem;
  border: 1px solid var(--test-cap-border);
  background: transparent;
  color: var(--test-cap-text);
}

[data-test-cap="link"] {
  color: var(--test-cap-accent);
}

:focus-visible {
  outline: 3px solid var(--test-cap-accent);
  outline-offset: 2px;
}

@media (prefers-reduced-motion: reduce) {
  * {
    transition: none !important;
    animation: none !important;
  }
}
`

/** One asset as the dispatcher serves it. */
export interface PageAsset {
  /** The path the page links to: the base, then `test-cap.<hash>.<extension>`. */
  readonly path: string
  /** The `Content-Type` to send. */
  readonly contentType: string
  /** The bytes to send, with immutable caching (ADR 0026). */
  readonly body: Uint8Array
}

/** The script and the stylesheet. */
export interface PageAssetSet {
  /** The browser script. */
  readonly script: PageAsset
  /** The optional stylesheet. */
  readonly style: PageAsset
}

const DIRECTORY = /^\/(?:[A-Za-z0-9._~-]+\/)*$/

async function asset(
  base: string,
  text: string,
  extension: string,
  contentType: string,
): Promise<PageAsset> {
  const body = utf8Encode(text)
  const hash = hexEncode(await sha256(body)).slice(0, 12)
  return { path: `${base}test-cap.${hash}.${extension}`, contentType, body }
}

/** The assets under `base` (default `/auth/assets/`), each named by the first 12 hex characters of its SHA-256. */
export async function pageAssets(base = "/auth/assets/"): Promise<PageAssetSet> {
  if (!DIRECTORY.test(base)) {
    throw new TypeError(
      "The asset base must be a directory path on this origin, such as /auth/assets/.",
    )
  }
  return {
    script: await asset(base, CLIENT_SCRIPT, "js", "text/javascript; charset=utf-8"),
    style: await asset(base, STYLESHEET, "css", "text/css; charset=utf-8"),
  }
}
