import { ACCOUNT_COLLECTION } from "../../src/core/accounts.js"
import type { AuthenticationEvidence } from "../../src/assurance/evidence.js"
import { defineAuthPolicy } from "../../src/assurance/policy.js"
import { type AuthConfig, createAuth, type EmailMessage } from "../../src/core/auth.js"
import { createAccount, IDENTIFIER_COLLECTION } from "../../src/core/accounts.js"
import { fixedClock, type FixedClock, systemRandom } from "../../src/core/clock.js"
import { base64UrlEncode } from "../../src/core/encoding.js"
import { parseKeyRing } from "../../src/core/mode.js"
import type { HibpFetch } from "../../src/methods/password/hibp.js"
import { setPassword } from "../../src/methods/password/method.js"
import { beginTotpEnrolment, confirmTotpEnrolment } from "../../src/methods/totp/method.js"
import type { SecurityEvent } from "../../src/ocsf/events.js"
import { createSessions } from "../../src/sessions/sessions.js"
import { memoryStore } from "../../src/store/memory.js"
import type { AuthStore } from "../../src/store/port.js"
import type { PlainRequest, PlainResponse } from "../../src/transport/types.js"
import { password as evidencePassword, T0, totp as evidenceTotp } from "./evidence.js"
import { codeAt } from "./totp.js"
import { TEST_ARGON2_COST, testHasher } from "./argon2.js"

export { T0 }
export const ORIGIN = "https://app.example"
export const TENANT = "default"
/** A password that passes the length, blocklist and context checks. */
export const PASSWORD = "correct horse battery staple"

/** A 32-byte key that does not look typed by hand, as `id:base64url`. */
export function keyRing(id: string, seed: number): string {
  return `${id}:${base64UrlEncode(Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + seed) % 256))}`
}

export const ENV = {
  APP_ENV: "test",
  APP_ORIGIN: ORIGIN,
  APP_SYSTEM_ID: "billing-web",
  AUTH_ENCRYPTION_KEY: keyRing("e1", 3),
  AUTH_CSRF_KEY: keyRing("c1", 5),
}

/** An HIBP range answer with only a padding row: the password is not breached. */
export const hibpClear: HibpFetch = () =>
  Promise.resolve({
    ok: true,
    status: 200,
    text: () => Promise.resolve("0000000000000000000000000000000000A:0"),
  })

/** A mail sender that sends nothing, for tests that never read an email. */
export const discardEmail = (): Promise<void> => Promise.resolve()

/** A mail sender that keeps every message in `outbox`, as the examples' in-memory outbox does. */
export function outboxSender(outbox: EmailMessage[]): (message: EmailMessage) => Promise<void> {
  return (message) => {
    outbox.push(message)
    return Promise.resolve()
  }
}

/**
 * An `Auth` over a memory store in test mode, a clock fixed at T0, argon2id at the test cost, a sink that records
 * every event, and a mail sender that keeps every email in `outbox`.
 */
export function testAuth(overrides: Partial<AuthConfig<string>> = {}) {
  const store: AuthStore = overrides.store ?? memoryStore()
  const clock: FixedClock = fixedClock(T0)
  const events: unknown[] = []
  const outbox: EmailMessage[] = []
  const auth = createAuth({
    store,
    env: ENV,
    clock,
    hibpFetch: hibpClear,
    argon2Cost: TEST_ARGON2_COST,
    sendEmail: outboxSender(outbox),
    onEvent: (event) => {
      events.push(event)
    },
    ...overrides,
  })
  return { auth, store, clock, events, outbox }
}

/** The confirmation code in the newest email to `identifier`; fails the test when there is none. */
export function confirmationCode(outbox: readonly EmailMessage[], identifier: string): string {
  const message = [...outbox].reverse().find((each) => each.to === identifier)
  const code = message === undefined ? undefined : /\b(\d{6})\b/.exec(message.text)?.[1]
  if (code === undefined) throw new Error(`no confirmation code was sent to ${identifier}`)
  return code
}

/** Confirms the address the browser's account signed up with, with the code from its newest email. */
export async function confirmEmail(
  browser: Browser,
  outbox: readonly EmailMessage[],
  identifier = "ada@example.com",
): Promise<Reply> {
  return expectOk(
    browser.post("/auth/email/confirm", { code: confirmationCode(outbox, identifier) }),
  )
}

/** What a transport answers. */
export interface Reply {
  readonly status: number
  readonly headers: Headers
  readonly text: string
  /** The body parsed as JSON; `undefined` when it is not JSON. */
  readonly json: unknown
}

/** One request a test sends. Headers are pairs, so a test can repeat one. */
export interface Outgoing {
  readonly method: string
  readonly path: string
  readonly headers?: readonly (readonly [string, string])[]
  readonly body?: string | Uint8Array | undefined
  /** The socket address the request comes from; `203.0.113.7` when left out. */
  readonly clientAddress?: string | undefined
}

/** Sends a request somewhere and returns the reply. */
export type Transport = (request: Outgoing) => Promise<Reply>

const decoder = new TextDecoder()

/** A reply built from a core response. */
export function replyOf(response: PlainResponse): Reply {
  const text = response.body === null ? "" : decoder.decode(response.body)
  return {
    status: response.status,
    headers: response.headers,
    text,
    json: (response.headers.get("content-type") ?? "").startsWith("application/json")
      ? (JSON.parse(text) as unknown)
      : undefined,
  }
}

/** The PlainRequest a test request becomes. */
export function plainRequest(request: Outgoing, signal?: AbortSignal): PlainRequest {
  const headers = new Headers()
  for (const [name, value] of request.headers ?? []) headers.append(name, value)
  const body = request.body
  return {
    method: request.method,
    url: request.path,
    headers,
    body:
      body === undefined ? null : typeof body === "string" ? new TextEncoder().encode(body) : body,
    clientAddress: request.clientAddress ?? "203.0.113.7",
    signal,
  }
}

/** Calls `auth.handle` in process; a `null` (outside /auth) reads as status 0. */
export function inProcess(auth: {
  handle(req: PlainRequest): Promise<PlainResponse | null>
}): Transport {
  return async (request) => {
    const response = await auth.handle(plainRequest(request))
    return response === null
      ? { status: 0, headers: new Headers(), text: "", json: undefined }
      : replyOf(response)
  }
}

/** The value a `Set-Cookie` line sets, or `null` when it removes the cookie. */
function cookieValue(line: string): { name: string; value: string | null } {
  const [pair = ""] = line.split(";")
  const equals = pair.indexOf("=")
  return {
    name: pair.slice(0, equals),
    value: /;\s*Max-Age=0(?:;|$)/i.test(line) ? null : pair.slice(equals + 1),
  }
}

/** A browser: keeps cookies and the synchronizer token, and sends `Origin` on every POST. */
export class Browser {
  readonly cookies = new Map<string, string>()
  csrf: string | null = null

  constructor(
    private readonly transport: Transport,
    readonly origin: string = ORIGIN,
  ) {}

  /** Sends `request` with the jar's cookies; `headers` replace nothing, they are added after the browser's. */
  async send(request: Outgoing): Promise<Reply> {
    const jar = [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ")
    const headers: (readonly [string, string])[] = jar === "" ? [] : [["Cookie", jar]]
    const reply = await this.transport({
      ...request,
      headers: [...headers, ...(request.headers ?? [])],
    })
    for (const line of reply.headers.getSetCookie()) {
      const { name, value } = cookieValue(line)
      if (value === null) this.cookies.delete(name)
      else this.cookies.set(name, value)
    }
    const issued = reply.headers.get("x-csrf-token")
    if (issued !== null) this.csrf = issued
    return reply
  }

  /** GET with the jar. */
  get(path: string): Promise<Reply> {
    return this.send({ method: "GET", path })
  }

  /** Fetches a synchronizer token from the session endpoint. */
  async start(): Promise<Reply> {
    const reply = await this.get("/auth/session")
    this.csrf = (reply.json as { csrfToken: string }).csrfToken
    return reply
  }

  /** A same-origin JSON POST carrying the synchronizer token, as test-cap/client sends it. */
  post(
    path: string,
    body: Record<string, unknown> = {},
    extra: Partial<Outgoing> = {},
  ): Promise<Reply> {
    return this.send({
      method: "POST",
      path,
      headers: [
        ["Origin", this.origin],
        ["Content-Type", "application/json"],
        ...(this.csrf === null ? [] : ([["X-CSRF-Token", this.csrf]] as const)),
        ...(extra.headers ?? []),
      ],
      body: JSON.stringify(body),
      clientAddress: extra.clientAddress,
    })
  }

  /** A same-origin form POST with the token in a hidden field, as the default pages send it. */
  postForm(path: string, fields: Record<string, string>): Promise<Reply> {
    return this.send({
      method: "POST",
      path,
      headers: [
        ["Origin", this.origin],
        ["Content-Type", "application/x-www-form-urlencoded"],
      ],
      body: new URLSearchParams({ ...fields, csrfToken: this.csrf ?? "" }).toString(),
    })
  }
}

/** Writes the confirmed identifier record that sign-in resolves, as a redeemed confirmation code does (F08). */
async function confirmIdentifier(
  store: AuthStore,
  identifier: string,
  accountId: string,
): Promise<void> {
  await store.createUnique(TENANT, {
    collection: IDENTIFIER_COLLECTION,
    key: identifier,
    owner: accountId,
    data: { account: accountId },
  })
}

/**
 * Signs up, confirms the address with the code from `outbox`, sets a password, enrols and confirms TOTP: the browser
 * ends holding an AAL2 session.
 */
export async function enrol(
  browser: Browser,
  clock: FixedClock,
  outbox: readonly EmailMessage[],
  identifier = "ada@example.com",
): Promise<{ subject: string; secret: string; identifier: string }> {
  if (browser.csrf === null) await browser.start()
  await expectOk(browser.post("/auth/sign-up", { identifier }))
  const session = await browser.get("/auth/session")
  const subject = (session.json as { session: { subject: string } }).session.subject
  await confirmEmail(browser, outbox, identifier)
  await expectOk(browser.post("/auth/password", { password: PASSWORD }))
  const enrolment = await expectOk(browser.post("/auth/totp/enrol"))
  const { authenticatorId, secret } = enrolment.json as { authenticatorId: string; secret: string }
  await expectOk(
    browser.post("/auth/totp/confirm", {
      authenticatorId,
      code: await codeAt(secret, clock.now()),
    }),
  )
  return { subject, secret, identifier }
}

/** An enrolled, confirmed account and a fresh browser that has not signed in. */
export async function account(
  setup: ReturnType<typeof testAuth>,
  identifier = "ada@example.com",
): Promise<{ subject: string; secret: string; identifier: string; browser: Browser }> {
  const enrolled = await enrol(
    new Browser(inProcess(setup.auth)),
    setup.clock,
    setup.outbox,
    identifier,
  )
  // The next TOTP code must be from a later time step than the one enrolment used.
  setup.clock.advance(30_000)
  const browser = new Browser(inProcess(setup.auth))
  await browser.start()
  return { ...enrolled, browser }
}

/** Fails the test with the reply's body when it is not a 2xx. */
export async function expectOk(pending: Promise<Reply>): Promise<Reply> {
  const reply = await pending
  if (reply.status < 200 || reply.status > 299) {
    throw new Error(`expected a 2xx, got ${reply.status} ${reply.text}`)
  }
  return reply
}

/** The test policy's twin: the same rules createAuth uses when it is given no policy. */
const defaultPolicy = defineAuthPolicy({ version: "test-cap default" })

/** Writes an account straight to the store, with a password and a confirmed TOTP when asked: no HTTP, no argon2 unless a password is asked for. */
export async function seedAccount(
  setup: ReturnType<typeof testAuth>,
  options: {
    readonly password?: boolean
    readonly totp?: boolean
    readonly identifier?: string
    /** False leaves the identifier unconfirmed, as a sign-up whose code was never redeemed. */
    readonly confirmed?: boolean
  } = {},
): Promise<{ subject: string; secret: string | null }> {
  const identifier = options.identifier ?? "ada@example.com"
  const subject = await createAccount(setup.store, TENANT, systemRandom, {
    identifier,
    now: setup.clock.now(),
  })
  if (options.confirmed !== false) await confirmIdentifier(setup.store, identifier, subject)
  if (options.password === true) {
    const set = await setPassword(
      {
        clock: setup.clock,
        random: systemRandom,
        store: setup.store,
        hibp: hibpClear,
        hasher: testHasher,
      },
      { tenant: TENANT, accountId: subject, password: PASSWORD, alone: false },
    )
    if (!set.ok) throw new Error(set.reason)
  }
  let secret: string | null = null
  if (options.totp === true) {
    const deps = {
      clock: setup.clock,
      random: systemRandom,
      store: setup.store,
      keyRing: parseKeyRing("AUTH_ENCRYPTION_KEY", ENV.AUTH_ENCRYPTION_KEY).keys,
    }
    const begun = await beginTotpEnrolment(deps, { tenant: TENANT, accountId: subject })
    const confirmed = await confirmTotpEnrolment(deps, {
      tenant: TENANT,
      accountId: subject,
      authenticatorId: begun.authenticatorId,
      code: await codeAt(begun.secret, setup.clock.now()),
    })
    if (!confirmed.ok) throw new Error(confirmed.reason)
    secret = begun.secret
    setup.clock.advance(30_000)
  }
  return { subject, secret }
}

/** A browser holding a session written straight to the store, with its synchronizer token. */
export async function seedSession(
  setup: ReturnType<typeof testAuth>,
  input: {
    readonly subject?: string
    readonly state?: "authenticated" | "pre-auth" | "recovery-only"
    readonly evidence?: readonly AuthenticationEvidence[]
  } = {},
): Promise<{ browser: Browser; token: string; id: string }> {
  const sessions = createSessions({
    store: setup.store,
    clock: setup.clock,
    random: systemRandom,
    policy: defaultPolicy,
  })
  const subject = input.subject ?? "acct-1"
  const evidence = input.evidence ?? []
  const state = input.state ?? "authenticated"
  // A session counts only for an active account (ADR 0012), so the subject gets one unless it already has a record.
  await setup.store.createUnique(TENANT, {
    collection: ACCOUNT_COLLECTION,
    key: subject,
    owner: subject,
    data: { status: "active", createdAt: setup.clock.now() },
  })
  const issued =
    state === "authenticated"
      ? await sessions.signIn(TENANT, null, { subject, evidence })
      : await sessions.begin(TENANT, null, { subject, state, evidence })
  const browser = new Browser(inProcess(setup.auth))
  browser.cookies.set("__Host-test-cap", issued.token)
  await browser.start()
  return { browser, token: issued.token, id: issued.id }
}

/** Password and TOTP evidence at the clock's time: an AAL2 session. */
export function aal2(clock: FixedClock): AuthenticationEvidence[] {
  return [evidencePassword({ at: clock.now() }), evidenceTotp({ at: clock.now() })]
}

/** Password evidence alone at the clock's time: an AAL1 session that a step-up must raise. */
export function aal1(clock: FixedClock): AuthenticationEvidence[] {
  return [evidencePassword({ at: clock.now() })]
}

/** The JSON body of a reply, typed loosely for assertions. */
export function body(reply: Reply): Record<string, unknown> {
  return reply.json as Record<string, unknown>
}

/**
 * A store that runs `before` ahead of every operation, so a test can change the store between a flow's read and its
 * write: the race a concurrent request would cause.
 */
export function hookedStore(
  base: AuthStore,
  before: (operation: string, args: readonly unknown[]) => Promise<void>,
): AuthStore {
  return new Proxy(base, {
    get(target, property, receiver) {
      const value: unknown = Reflect.get(target, property, receiver)
      if (typeof value !== "function" || property === "transaction") return value
      return async (...args: unknown[]) => {
        await before(String(property), args)
        return (value as (...a: unknown[]) => Promise<unknown>).apply(target, args)
      }
    },
  })
}

/** The OCSF type ids of the phase 3 activities (ADR 0015 §2): class_uid * 100 + activity_id. */
export const LOGON = 300201
export const LOGOFF = 300202
export const CREATE = 300701
export const UPDATE = 300702
export const ENABLE_MFA = 300712

/** The parts of an OCSF event a flow test pins: type, status, user, detail, factors, step-up and session prefix. */
export function brief(event: unknown): Record<string, unknown> {
  const e = event as SecurityEvent
  return {
    type: e.type_uid,
    status: e.status,
    user: e.user.uid,
    ...(e.status_detail === undefined ? {} : { detail: e.status_detail }),
    ...(e.auth_factors === undefined ? {} : { factors: e.auth_factors.map((f) => f.factor_type) }),
    ...(e.unmapped.test_cap.step_up === true ? { stepUp: true } : {}),
    ...(e.class_uid === 3002 && e.session !== undefined ? { session: e.session.uid } : {}),
  }
}

export { internalsOf as internalsOfAuth } from "../../src/core/auth.js"
