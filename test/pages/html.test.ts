import { describe, expect, it } from "vitest"
import { escapeHtml, join, markup } from "../../src/pages/html.js"

describe("escapeHtml", () => {
  it("escapes the five characters that can break out of text or a quoted attribute", () => {
    expect(escapeHtml(`<a href="x" title='y'>&</a>`)).toBe(
      "&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;",
    )
  })

  it("leaves other text alone, including non-ASCII", () => {
    expect(escapeHtml("Jürgen 🔐 / = ` ")).toBe("Jürgen 🔐 / = ` ")
  })
})

describe("markup", () => {
  it("escapes every interpolated string", () => {
    const hostile = `"><script>alert(1)</script>`
    expect(markup`<p title="${hostile}">${hostile}</p>`.value).toBe(
      '<p title="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;">&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;</p>',
    )
  })

  it("inserts nested fragments as they are, since they were escaped when built", () => {
    const inner = markup`<b>${"<i>"}</b>`
    expect(markup`<p>${inner}</p>`.value).toBe("<p><b>&lt;i&gt;</b></p>")
  })

  it("writes numbers as text and leaves nothing for null, undefined or false", () => {
    expect(markup`<p>${3}${null}${undefined}${false}</p>`.value).toBe("<p>3</p>")
  })

  it("joins a list of fragments without a separator", () => {
    expect(join([markup`<i>${"a"}</i>`, markup`<i>${"<"}</i>`]).value).toBe("<i>a</i><i>&lt;</i>")
    expect(join([]).value).toBe("")
  })
})
