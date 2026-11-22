/**
 * Server-side sessions (ADR 0006). The client holds an opaque 256-bit token; the store holds only its SHA-256. Every
 * read goes to the store and recomputes the assurance from the evidence (ADR 0005 §2): there is no cache to skip
 * revocation or the assurance check. Every change of trust issues a new token and revokes the old one.
 */

import type { AuthenticationEvidence } from "../assurance/evidence.js"
import type {
  AuthPolicy,
  RequireResult,
  SessionAssurance,
  SessionKind,
  SessionState,
} from "../assurance/policy.js"
import { randomToken, type Clock, type RandomSource } from "../core/clock.js"
import { hexEncode, sha256, utf8Encode } from "../core/encoding.js"
import type {
  AuthStore,
  JsonValue,
  StoredRecord,
  StoreOperations,
  TenantId,
} from "../store/port.js"
import { expireCookie, readCookie, serializeCookie } from "../transport/cookies.js"

/** The session cookie's name (ADR 0006 §2). */
const SESSION_COOKIE = "__Host-test-cap"

/** The collection session records live in, keyed by the SHA-256 of the token and owned by the subject. */
export const SESSION_COLLECTION = "session"
const COOKIE_ATTRIBUTES = { httpOnly: true, sameSite: "Lax" } as const
const STEP_UP = "step-up"
/** How long a step-up challenge can be used: the lifetime ADR 0006 §3 gives a federation transaction. */
const STEP_UP_LIFETIME_MS = 10 * 60_000
/** A step-up challenge is 16 random bytes in unpadded base64url. */
const CHALLENGE_FORMAT = /^[A-Za-z0-9_-]{22}$/
/** A token is 32 random bytes in unpadded base64url. */
const TOKEN_FORMAT = /^[A-Za-z0-9_-]{43}$/

/** The `Set-Cookie` value that carries `token` for `lifetimeMs`, rounded down to whole seconds. */
export function sessionCookie(token: string, lifetimeMs: number): string {
  return serializeCookie(SESSION_COOKIE, token, {
    ...COOKIE_ATTRIBUTES,
    maxAge: Math.floor(lifetimeMs / 1000),
  })
}

/** The `Set-Cookie` value that removes the session cookie. */
export function clearSessionCookie(): string {
  return expireCookie(SESSION_COOKIE, COOKIE_ATTRIBUTES)
}

/** The session token a request carries; `null` when absent or when the cookie arrives twice (cookie tossing). */
export function readSessionToken(headers: Headers): string | null {
  const read = readCookie(headers, SESSION_COOKIE)
  return read.kind === "value" ? read.value : null
}

/** A session just issued. */
export interface IssuedSession {
  /** The token, for the cookie only; never stored. */
  readonly token: string
  /** The session's public id, for the session list. */
  readonly id: string
  /** The `Set-Cookie` value carrying the token. */
  readonly cookie: string
  /** What the session holds. */
  readonly state: SessionState
}

/** A session as read, before this read's activity is recorded. */
export interface ReadSession {
  /** The session's public id. */
  readonly id: string
  /** What the session holds. */
  readonly state: SessionState
  /** The assurance its evidence supports at the time of the read (ADR 0005 §2). */
  readonly assurance: SessionAssurance
}

/** One line of a person's session list. */
export interface SessionSummary {
  /** The session's public id, which `revoke` takes. */
  readonly id: string
  /** True for the session that asked. */
  readonly current: boolean
  /** The session's state. */
  readonly state: SessionKind
  /** When the session entered its state. */
  readonly startedAt: number
  /** The last request it served. */
  readonly lastSeenAt: number
  /** The methods of its evidence still valid. */
  readonly methods: readonly string[]
}

/** What `createSessions` needs. */
export interface SessionOptions<Id extends string> {
  /** The store holding the session records. */
  readonly store: AuthStore
  /** The injected clock. */
  readonly clock: Clock
  /** The injected random source the tokens come from. */
  readonly random: RandomSource
  /** The policy that computes each session's assurance and limits. */
  readonly policy: AuthPolicy<Id>
}

interface SessionData extends SessionState {
  readonly id: string
  /** Set when a rotation claimed the record; it is dead from then on, before its revocation lands. */
  readonly rotatedAt?: number
}

interface Found {
  readonly key: string
  readonly record: StoredRecord
  readonly data: SessionData
}

interface Loaded extends Found {
  readonly assurance: SessionAssurance
}

/** The newest item of each key, oldest first; of two at the same time, the one listed later. */
function newestEach<T extends { readonly at: number }>(
  items: readonly T[],
  keyOf: (item: T) => string,
): T[] {
  const newest = new Map<string, T>()
  for (const item of items) {
    const kept = newest.get(keyOf(item))
    if (kept === undefined || item.at >= kept.at) newest.set(keyOf(item), item)
  }
  return [...newest.values()].sort((a, b) => a.at - b.at)
}

/**
 * The state a session stores (ADR 0005 §2): the newest evidence of each (method, authenticator) and the newest step-up
 * of each method, which is all the level rules and recency times need. A session cannot grow, nor slow its own reads,
 * by repeating a ceremony.
 */
function bounded(state: SessionState): SessionState {
  return {
    ...state,
    evidence: newestEach(state.evidence, (item) =>
      JSON.stringify([item.method, item.authenticatorId]),
    ),
    stepUps: newestEach(state.stepUps, (item) => item.method),
  }
}

/** True for a token test-cap could have issued. `null` reads as the four letters "null", which no token matches. */
function wellFormed(token: string | null): token is string {
  return TOKEN_FORMAT.test(String(token))
}

async function hashToken(token: string): Promise<string> {
  return hexEncode(await sha256(utf8Encode(token)))
}

/** Sessions over the store: sign-in, rotation, sign-out, the session list and remote revoke. */
export function createSessions<Id extends string>(options: SessionOptions<Id>) {
  const { store, clock, random, policy } = options

  const absoluteMs = (state: SessionKind): number =>
    state === "authenticated"
      ? policy.timeouts.aal2AbsoluteMs
      : policy.timeouts.restrictedAbsoluteMs

  /** The record behind `token` while it stands: not revoked and not claimed by a rotation. */
  const find = async (
    ops: StoreOperations,
    tenant: TenantId,
    token: string | null,
  ): Promise<Found | null> => {
    if (!wellFormed(token)) return null
    const key = await hashToken(token)
    const record = await ops.get(tenant, SESSION_COLLECTION, key)
    if (record === null || record.revokedAt !== null) return null
    const data = record.data as unknown as SessionData
    return data.rotatedAt === undefined ? { key, record, data } : null
  }

  const load = async (
    ops: StoreOperations,
    tenant: TenantId,
    token: string | null,
    now: number,
  ): Promise<Loaded | null> => {
    const found = await find(ops, tenant, token)
    if (found === null) return null
    const assurance = policy.assurance(found.data, now)
    return assurance === null ? null : { ...found, assurance }
  }

  const create = async (
    ops: StoreOperations,
    tenant: TenantId,
    unbounded: SessionState,
    now: number,
  ): Promise<{ readonly key: string; readonly issued: IssuedSession }> => {
    const state = bounded(unbounded)
    const token = randomToken(random)
    const id = randomToken(random, 16)
    const key = await hashToken(token)
    const expiresAt = state.startedAt + absoluteMs(state.state)
    const data: SessionData = { id, ...state }
    const created = await ops.createUnique(tenant, {
      collection: SESSION_COLLECTION,
      key,
      owner: state.subject,
      expiresAt,
      data: data as unknown as JsonValue,
    })
    if (created === "exists") {
      throw new Error(
        "A new session token collided with a stored one; the random source is broken.",
      )
    }
    return { key, issued: { token, id, cookie: sessionCookie(token, expiresAt - now), state } }
  }

  const issue = async (
    tenant: TenantId,
    state: SessionState,
    now: number,
  ): Promise<IssuedSession> => (await create(store, tenant, state, now)).issued

  /** Replaces the session behind `token` with `change(state)`, in one transaction when the store has them. */
  const replace = async (
    tenant: TenantId,
    token: string,
    change: (state: SessionState, now: number) => SessionState | null,
    revokeOthers = false,
  ): Promise<IssuedSession | null> => {
    const now = clock.now()
    const run = async (ops: StoreOperations): Promise<IssuedSession | null> => {
      const current = await load(ops, tenant, token, now)
      if (current === null) return null
      const next = change(current.data, now)
      if (next === null) return null
      // Claiming the record first lets exactly one of two concurrent rotations of one token through.
      const claim: SessionData = { ...current.data, rotatedAt: now }
      const claimed = await ops.update(
        tenant,
        SESSION_COLLECTION,
        current.key,
        current.record.version,
        {
          data: claim as unknown as JsonValue,
        },
      )
      if (claimed !== "updated") return null
      const { key, issued } = await create(ops, tenant, next, now)
      await ops.revoke(tenant, SESSION_COLLECTION, current.key, now)
      if (revokeOthers)
        await ops.revokeByOwner(tenant, SESSION_COLLECTION, next.subject, now, { except: key })
      return issued
    }
    return store.transaction === undefined ? run(store) : store.transaction(run)
  }

  const revokePresented = async (
    tenant: TenantId,
    token: string | null,
    now: number,
  ): Promise<void> => {
    if (!wellFormed(token)) return
    await store.revoke(tenant, SESSION_COLLECTION, await hashToken(token), now)
  }

  /**
   * Reads the session and records this request as its activity. A session found past its idle or absolute limit is
   * revoked, so a clock that later jumps backwards cannot give it the rest of its window again (ADR 0006 §4). The
   * answer is `null` whether or not that revoke lands; a revoke that failed is tried again by the next read.
   */
  const read = async (tenant: TenantId, token: string | null): Promise<ReadSession | null> => {
    const now = clock.now()
    const found = await find(store, tenant, token)
    if (found === null) return null
    const assurance = policy.assurance(found.data, now)
    if (assurance === null) {
      try {
        await store.revoke(tenant, SESSION_COLLECTION, found.key, now)
      } catch {
        // The session already answers unauthenticated; a failed revoke changes no reply.
      }
      return null
    }
    const { id, ...state } = found.data
    const touched: SessionData = { ...found.data, lastSeenAt: now }
    await store.update(tenant, SESSION_COLLECTION, found.key, found.record.version, {
      data: touched as unknown as JsonValue,
    })
    return { id, state, assurance }
  }

  return {
    /** Signs in: always a new session. A presented token is revoked, never adopted (ADR 0006 §5). */
    async signIn(
      tenant: TenantId,
      presented: string | null,
      input: { readonly subject: string; readonly evidence: readonly AuthenticationEvidence[] },
    ): Promise<IssuedSession> {
      const now = clock.now()
      await revokePresented(tenant, presented, now)
      return issue(
        tenant,
        {
          subject: input.subject,
          state: "authenticated",
          evidence: input.evidence,
          stepUps: [],
          startedAt: now,
          lastSeenAt: now,
        },
        now,
      )
    },

    /** Starts a pre-auth or recovery-only session; a presented token is revoked, never adopted. */
    async begin(
      tenant: TenantId,
      presented: string | null,
      input: {
        readonly subject: string
        readonly state: "pre-auth" | "recovery-only"
        readonly evidence?: readonly AuthenticationEvidence[]
      },
    ): Promise<IssuedSession> {
      const now = clock.now()
      await revokePresented(tenant, presented, now)
      return issue(
        tenant,
        {
          subject: input.subject,
          state: input.state,
          evidence: input.evidence ?? [],
          stepUps: [],
          startedAt: now,
          lastSeenAt: now,
        },
        now,
      )
    },

    read,

    /** Reads the session from the store and answers the requirement under `id` (ADR 0005 §7). */
    async require(tenant: TenantId, token: string | null, id: Id): Promise<RequireResult> {
      const session = await read(tenant, token)
      return policy.require(session?.state ?? null, id, clock.now())
    },

    /**
     * Opens a step-up for an authenticated session: a single-use challenge, bound to this session, that the step-up
     * ceremony must return within 10 minutes. `null` for any other session.
     */
    async beginStepUp(tenant: TenantId, token: string | null): Promise<string | null> {
      const now = clock.now()
      const current = await load(store, tenant, token, now)
      if (current?.data.state !== "authenticated") return null
      const challenge = randomToken(random, 16)
      const created = await store.createUnique(tenant, {
        collection: STEP_UP,
        key: challenge,
        owner: null,
        expiresAt: now + STEP_UP_LIFETIME_MS,
        data: current.key,
      })
      if (created === "exists") {
        throw new Error(
          "A new step-up challenge collided with a stored one; the random source is broken.",
        )
      }
      return challenge
    },

    /**
     * Adds step-up evidence to the session and rotates it, only when `challenge` was opened by this same session and
     * is unused and unexpired (ADR 0005, ADR 0006 §5).
     */
    async stepUp(
      tenant: TenantId,
      token: string,
      challenge: string,
      evidence: AuthenticationEvidence,
    ): Promise<IssuedSession | null> {
      if (!CHALLENGE_FORMAT.test(challenge)) return null
      const now = clock.now()
      const current = await load(store, tenant, token, now)
      const bound = await store.get(tenant, STEP_UP, challenge)
      if (current === null || bound?.data !== current.key) return null
      if ((await store.consumeOnce(tenant, STEP_UP, challenge, now)) === null) return null
      return replace(tenant, token, (state, at) => ({
        ...state,
        evidence: [...state.evidence, evidence],
        stepUps: [...state.stepUps, { at, method: evidence.method }],
        lastSeenAt: at,
      }))
    },

    /** Ends enrolment: the pre-auth session becomes a new authenticated one, holding its evidence and the new. */
    completeEnrolment(
      tenant: TenantId,
      token: string,
      evidence: readonly AuthenticationEvidence[],
    ): Promise<IssuedSession | null> {
      return replace(tenant, token, (state, now) =>
        state.state === "pre-auth"
          ? {
              ...state,
              state: "authenticated",
              evidence: [...state.evidence, ...evidence],
              startedAt: now,
              lastSeenAt: now,
            }
          : null,
      )
    },

    /**
     * Rotates the session on a change of trust that changes nothing it holds: a privilege change, and the start and
     * end of impersonation or break-glass (ADR 0006 §5 and Open 4).
     */
    rotate(tenant: TenantId, token: string): Promise<IssuedSession | null> {
      return replace(tenant, token, (state, now) => ({ ...state, lastSeenAt: now }))
    },

    /** A credential changed: rotates this session and revokes the account's others (ADR 0006 §7). */
    credentialChanged(tenant: TenantId, token: string): Promise<IssuedSession | null> {
      return replace(tenant, token, (state, now) => ({ ...state, lastSeenAt: now }), true)
    },

    /** Ends a recovery-only session once recovery finishes (ADR 0007 Open 5); returns the cookie clearing. */
    async endRecovery(tenant: TenantId, token: string): Promise<string> {
      await revokePresented(tenant, token, clock.now())
      return clearSessionCookie()
    },

    /** Signs out: revokes the session the token names and returns the cookie clearing. */
    async signOut(tenant: TenantId, token: string | null): Promise<string> {
      await revokePresented(tenant, token, clock.now())
      return clearSessionCookie()
    },

    /** The caller's own live sessions; `null` without a valid session. */
    async list(tenant: TenantId, token: string | null): Promise<readonly SessionSummary[] | null> {
      const now = clock.now()
      const current = await load(store, tenant, token, now)
      if (current === null) return null
      const records = await store.listByOwner(tenant, SESSION_COLLECTION, current.data.subject)
      const summaries: SessionSummary[] = []
      for (const record of records) {
        const data = record.data as unknown as SessionData
        const assurance = record.revokedAt === null ? policy.assurance(data, now) : null
        if (assurance === null) continue
        summaries.push({
          id: data.id,
          current: record.key === current.key,
          state: data.state,
          startedAt: data.startedAt,
          lastSeenAt: data.lastSeenAt,
          methods: assurance.evidence.map((item) => item.method),
        })
      }
      return summaries
    },

    /** Revokes one of the caller's own sessions by its public id; `false` for any other id. */
    async revoke(tenant: TenantId, token: string | null, sessionId: string): Promise<boolean> {
      const now = clock.now()
      const current = await load(store, tenant, token, now)
      if (current === null) return false
      const records = await store.listByOwner(tenant, SESSION_COLLECTION, current.data.subject)
      const target = records.find(
        (record) =>
          record.revokedAt === null && (record.data as unknown as SessionData).id === sessionId,
      )
      if (target === undefined) return false
      return store.revoke(tenant, SESSION_COLLECTION, target.key, now)
    },
  }
}
