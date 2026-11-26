import type { RequireResult } from "../../src/assurance/policy.js"
import type { SessionInfo } from "../../src/core/auth.js"
import { systemRandom } from "../../src/core/clock.js"
import { createHasher } from "../../src/methods/password/argon2.js"
import { setPassword } from "../../src/methods/password/method.js"
import {
  aal1,
  aal2,
  Browser,
  confirmationCode,
  expectOk,
  inProcess,
  PASSWORD,
  plainRequest,
  type Reply,
  seedAccount,
  seedSession,
  TENANT,
  testAuth,
} from "./auth.js"
import { faultyStore, type StoreOperation } from "./faulty-store.js"
import { codeAt } from "./totp.js"

/** What a browser's cookie holds, read through the public API once the store works again. */
export interface Standing {
  readonly session: SessionInfo | null
  readonly outcome: RequireResult["outcome"]
}

/** A flow ready to run once: everything before the faulted request is done with a working store. */
interface Prepared {
  /** Sends the request the fault is injected into. */
  readonly run: () => Promise<Reply>
  /** The browser's standing before the request. */
  readonly before: Standing
  /** The browser's standing now, through a store no fault reaches. */
  readonly standing: () => Promise<Standing>
  /** The status and body the flow answers when nothing fails. */
  readonly success: { readonly status: number; readonly outcome: unknown }
}

/** One flow of phase 3 that reads or writes the store. */
export interface Flow {
  readonly name: string
  /**
   * Every store call the flow makes, in order, when nothing fails. specs/dependency-failures.md lists the same, and
   * test/failure/store.test.ts fails a flow that calls anything else until its failure cases cover it.
   */
  readonly profile: readonly StoreOperation[]
  /** Sets up the flow over `faulty`'s store and returns it ready to run. */
  readonly prepare: (faulty: ReturnType<typeof faultyStore>) => Promise<Prepared>
}

/** An `Auth` over a faulty store, in test mode. */
function faultyAuth(faulty: ReturnType<typeof faultyStore>) {
  return testAuth({ store: faulty.store })
}

/** The standing of the session cookie `browser` holds, read by `auth.session` and `auth.require`. */
async function standingOf(setup: ReturnType<typeof testAuth>, browser: Browser): Promise<Standing> {
  const cookie = [...browser.cookies].map(([name, value]) => `${name}=${value}`).join("; ")
  const request = () =>
    plainRequest({ method: "GET", path: "/", headers: cookie === "" ? [] : [["Cookie", cookie]] })
  const session = await setup.auth.session(request())
  const { outcome } = await setup.auth.require(request(), "default")
  return { session, outcome }
}

function prepared(
  setup: ReturnType<typeof testAuth>,
  browser: Browser,
  before: Standing,
  run: () => Promise<Reply>,
  success: Prepared["success"],
): Prepared {
  return { run, before, standing: () => standingOf(setup, browser), success }
}

/** The flows the failure tests inject store faults into, each from the state a person reaches it in. */
export const FLOWS: readonly Flow[] = [
  {
    // F02: a browser already holding a password session signs in again, so the presented token is revoked first.
    name: "password sign-in",
    profile: [
      "increment",
      "get",
      "get",
      "get",
      "get",
      "get",
      "get",
      "increment",
      "increment",
      "get",
      "get",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "listByOwner",
      "revoke",
      "createUnique",
      "get",
    ],
    async prepare(faulty) {
      const setup = faultyAuth(faulty)
      const { subject } = await seedAccount(setup, { password: true, totp: true })
      const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
      const before = await standingOf(setup, browser)
      const run = () =>
        browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
      return prepared(setup, browser, before, run, { status: 200, outcome: "step-up" })
    },
  },
  {
    // F08: a pre-auth session redeems the right confirmation code.
    name: "email confirmation",
    profile: [
      "increment",
      "get",
      "get",
      "update",
      "listByOwner",
      "listByOwner",
      "increment",
      "consumeOnce",
      "createUnique",
    ],
    async prepare(faulty) {
      const setup = faultyAuth(faulty)
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      await expectOk(browser.post("/auth/sign-up", { identifier: "ada@example.com" }))
      const code = confirmationCode(setup.outbox, "ada@example.com")
      const before = await standingOf(setup, browser)
      const run = () => browser.post("/auth/email/confirm", { code })
      return prepared(setup, browser, before, run, { status: 200, outcome: "enroll" })
    },
  },
  {
    // F04: a password session completes its second factor with the right TOTP code.
    name: "TOTP verification",
    profile: [
      "increment",
      "get",
      "get",
      "update",
      "get",
      "listByOwner",
      "get",
      "get",
      "get",
      "increment",
      "increment",
      "listByOwner",
      "get",
      "update",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "get",
      "get",
      "createUnique",
      "get",
      "get",
      "get",
      "consumeOnce",
      "get",
      "get",
      "update",
      "createUnique",
      "revoke",
    ],
    async prepare(faulty) {
      const setup = faultyAuth(faulty)
      const { subject, secret } = await seedAccount(setup, { password: true, totp: true })
      const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
      const code = await codeAt(String(secret), setup.clock.now())
      const before = await standingOf(setup, browser)
      const run = () => browser.post("/auth/totp/verify", { code })
      return prepared(setup, browser, before, run, { status: 200, outcome: "allow" })
    },
  },
  {
    // F13: a password session opens a step-up challenge and answers it with the right TOTP code.
    name: "step-up",
    profile: [
      "increment",
      "get",
      "get",
      "update",
      "get",
      "get",
      "createUnique",
      "increment",
      "get",
      "get",
      "update",
      "get",
      "get",
      "listByOwner",
      "get",
      "get",
      "get",
      "increment",
      "increment",
      "listByOwner",
      "get",
      "update",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "get",
      "get",
      "get",
      "consumeOnce",
      "get",
      "get",
      "update",
      "createUnique",
      "revoke",
    ],
    async prepare(faulty) {
      const setup = faultyAuth(faulty)
      const { subject, secret } = await seedAccount(setup, { password: true, totp: true })
      const { browser } = await seedSession(setup, { subject, evidence: aal1(setup.clock) })
      const code = await codeAt(String(secret), setup.clock.now())
      const before = await standingOf(setup, browser)
      const run = async () => {
        const started = await browser.post("/auth/step-up/start")
        if (started.status !== 200) return started
        const { challenge } = started.json as { challenge: string }
        return browser.post("/auth/step-up", { challenge, code })
      }
      return prepared(setup, browser, before, run, { status: 200, outcome: "allow" })
    },
  },
  {
    // F14: an AAL2 session reads itself through the session route.
    name: "session read",
    profile: ["increment", "get", "get", "update"],
    async prepare(faulty) {
      const setup = faultyAuth(faulty)
      const { browser } = await seedSession(setup, { evidence: aal2(setup.clock) })
      const before = await standingOf(setup, browser)
      const run = () => browser.get("/auth/session")
      return prepared(setup, browser, before, run, { status: 200, outcome: undefined })
    },
  },
  {
    // F02 with an outdated argon2id cost: the verified password is re-hashed and written back before the session.
    name: "password sign-in with rehash",
    profile: [
      "increment",
      "get",
      "get",
      "get",
      "get",
      "get",
      "get",
      "increment",
      "increment",
      "get",
      "get",
      "resetCounter",
      "delete",
      "update",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "resetCounter",
      "delete",
      "listByOwner",
      "createUnique",
      "get",
    ],
    async prepare(faulty) {
      const setup = faultyAuth(faulty)
      const { subject } = await seedAccount(setup, { totp: true })
      const older = createHasher({ memoryKiB: 8, iterations: 2, parallelism: 1 })
      const deps = {
        clock: setup.clock,
        random: systemRandom,
        store: setup.store,
        hibp: "off" as const,
      }
      await setPassword(
        { ...deps, hasher: older },
        { tenant: TENANT, accountId: subject, password: PASSWORD, alone: false },
      )
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      const before = await standingOf(setup, browser)
      const run = () =>
        browser.post("/auth/sign-in", { identifier: "ada@example.com", password: PASSWORD })
      return prepared(setup, browser, before, run, { status: 200, outcome: "step-up" })
    },
  },
  {
    // F01: a new browser signs up; the account, its unconfirmed address, the code and the pre-auth session are written.
    name: "sign-up",
    profile: [
      "increment",
      "createUnique",
      "createUnique",
      "increment",
      "increment",
      "increment",
      "revokeByOwner",
      "resetCounter",
      "delete",
      "createUnique",
      "createUnique",
    ],
    async prepare(faulty) {
      const setup = faultyAuth(faulty)
      const browser = new Browser(inProcess(setup.auth))
      await browser.start()
      const before = await standingOf(setup, browser)
      const run = () => browser.post("/auth/sign-up", { identifier: "ada@example.com" })
      return prepared(setup, browser, before, run, { status: 200, outcome: "enroll" })
    },
  },
  {
    // F03 on a signed-in account: confirming a second TOTP is a credential change, which rotates the session.
    name: "TOTP enrolment by a signed-in account",
    profile: [
      "increment",
      "get",
      "get",
      "update",
      "get",
      "get",
      "update",
      "get",
      "get",
      "update",
      "createUnique",
      "revoke",
      "revokeByOwner",
    ],
    async prepare(faulty) {
      const setup = faultyAuth(faulty)
      const { subject } = await seedAccount(setup, { password: true, totp: true })
      const { browser } = await seedSession(setup, { subject, evidence: aal2(setup.clock) })
      const begun = await expectOk(browser.post("/auth/totp/enrol"))
      const { authenticatorId, secret } = begun.json as { authenticatorId: string; secret: string }
      const code = await codeAt(secret, setup.clock.now())
      const before = await standingOf(setup, browser)
      const run = () => browser.post("/auth/totp/confirm", { authenticatorId, code })
      return prepared(setup, browser, before, run, { status: 200, outcome: "allow" })
    },
  },
  {
    // F14: an AAL2 session signs out.
    name: "sign-out",
    profile: ["increment", "get", "get", "update", "revoke"],
    async prepare(faulty) {
      const setup = faultyAuth(faulty)
      const { browser } = await seedSession(setup, { evidence: aal2(setup.clock) })
      const before = await standingOf(setup, browser)
      const run = () => browser.post("/auth/sign-out")
      return prepared(setup, browser, before, run, { status: 200, outcome: "unauthenticated" })
    },
  },
]
