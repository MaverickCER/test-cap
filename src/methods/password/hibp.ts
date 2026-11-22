/**
 * The HIBP range check (ADR 0010 §2 to §4). Only the first 5 hex characters of the password's SHA-1 leave the process,
 * with `Add-Padding: true`. A matching suffix with a count above zero is a breach; a count of 0 is a padding row. An
 * answer that does not come, comes late, is an error or cannot be read is `indeterminate`, never a pass. The host is
 * fixed here; the fetch is injected, so tests never reach the real service.
 */

import { hexEncode, utf8Encode } from "../../core/encoding.js"
import type { NormalisedPassword } from "./rules.js"

/** The outcome of one range check. */
export type BreachScreening = "clear" | "breached" | "indeterminate"

/** The part of a fetch response the check reads. */
export interface HibpResponse {
  /** True for a 2xx status. */
  readonly ok: boolean
  /** The HTTP status. */
  readonly status: number
  /** The body as text. */
  text(): Promise<string>
}

/** The fetch the check calls; the global `fetch` fits it. */
export type HibpFetch = (
  url: string,
  init: {
    readonly method: "GET"
    readonly headers: Readonly<Record<string, string>>
    readonly signal: AbortSignal
  },
) => Promise<HibpResponse>

/** After this long without an answer the result is `indeterminate` (ADR 0010 Open 3). */
export const HIBP_TIMEOUT_MS = 1_500

const RANGE_ENDPOINT = "https://api.pwnedpasswords.com/range/"
const ROW = /^([0-9A-F]{35}):(\d+)$/i

async function sha1Hex(password: NormalisedPassword): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", utf8Encode(password))
  return hexEncode(new Uint8Array(digest)).toUpperCase()
}

function readRange(body: string, suffix: string): BreachScreening {
  const rows = body
    .split("\n")
    .map((line) => ROW.exec(line.trim()))
    .filter((match) => match !== null)
  if (rows.length === 0) return "indeterminate"
  const breached = rows.some(
    (match) => String(match[1]).toUpperCase() === suffix && Number(match[2]) > 0,
  )
  return breached ? "breached" : "clear"
}

async function query(
  password: NormalisedPassword,
  fetch: HibpFetch,
  signal: AbortSignal,
): Promise<BreachScreening> {
  const hash = await sha1Hex(password)
  const response = await fetch(`${RANGE_ENDPOINT}${hash.slice(0, 5)}`, {
    method: "GET",
    headers: { "Add-Padding": "true" },
    signal,
  })
  if (!response.ok) return "indeterminate"
  return readRange(await response.text(), hash.slice(5))
}

/** Screens `password` against the HIBP breach corpus. Never rejects. */
export async function screenWithHibp(
  password: NormalisedPassword,
  fetch: HibpFetch,
): Promise<BreachScreening> {
  const controller = new AbortController()
  let timer: ReturnType<typeof setTimeout> | undefined
  const timeout = new Promise<BreachScreening>((resolve) => {
    timer = setTimeout(() => {
      controller.abort()
      resolve("indeterminate")
    }, HIBP_TIMEOUT_MS)
  })
  try {
    return await Promise.race([query(password, fetch, controller.signal), timeout])
  } catch {
    return "indeterminate"
  } finally {
    clearTimeout(timer)
  }
}
