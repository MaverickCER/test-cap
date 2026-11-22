/**
 * The auth policy (ADR 0005 §4, §6, §7): requirements under test-cap's own ids, the deviations that relax a strict
 * default, session assurance recomputed from the evidence still valid on every read (ADR 0005 §2), the timeouts of
 * ADR 0006 §4, and `require` with its five outcomes. Pure: no clock, store or request is read here.
 */

import { ConfigError } from "../core/errors.js"
import type { AssuranceLevel, AuthenticationEvidence, AuthenticationMethod } from "./evidence.js"
import { atLeast, levelOf, recency, type TrustConfig } from "./levels.js"

/** What a route or operation needs from the session's assurance. */
export interface Requirement {
  /** The lowest level that satisfies it. */
  readonly level: AssuranceLevel
  /** True when the session must hold phishing-resistant evidence. */
  readonly phishingResistant?: boolean | undefined
  /** How recent, in milliseconds, the evidence proving multiple factors must be. */
  readonly multiFactorWithinMs?: number | undefined
  /** How recent, in milliseconds, the last phishing-resistant ceremony must be. */
  readonly phishingResistantWithinMs?: number | undefined
}

/** The idle and absolute session limits, in milliseconds (ADR 0006 §4 and Open 2). */
export interface SessionTimeouts {
  /** Inactivity after which an authenticated session ends. */
  readonly aal2IdleMs: number
  /** Age after which an authenticated session ends, and after which a piece of evidence stops counting. */
  readonly aal2AbsoluteMs: number
  /** Inactivity after which no evidence counts towards AAL3. */
  readonly aal3IdleMs: number
  /** Age after which a piece of evidence stops counting towards AAL3. */
  readonly aal3AbsoluteMs: number
  /** Inactivity after which a pre-auth or recovery-only session ends. */
  readonly restrictedIdleMs: number
  /** Age after which a pre-auth or recovery-only session ends. */
  readonly restrictedAbsoluteMs: number
}

const MINUTE = 60_000
const HOUR = 60 * MINUTE

/** The ADR 0006 limits. Shortening one is free; lengthening one is a deviation. */
export const DEFAULT_TIMEOUTS: SessionTimeouts = {
  aal2IdleMs: HOUR,
  aal2AbsoluteMs: 24 * HOUR,
  aal3IdleMs: 15 * MINUTE,
  aal3AbsoluteMs: 12 * HOUR,
  restrictedIdleMs: 15 * MINUTE,
  restrictedAbsoluteMs: HOUR,
}

/** A line of the policy that relaxes a strict default (ADR 0005 §6). */
export interface Deviation {
  /** Which default it relaxes. */
  readonly kind: "email-sign-in" | "default-below-aal2" | "timeout-lengthened"
  /** One sentence for the policy report. */
  readonly detail: string
}

/** What `defineAuthPolicy` takes. */
export interface AuthPolicyInput<Id extends string> {
  /** Names this policy, so a report can say which one computed a session's assurance. */
  readonly version: string
  /** The requirements, by test-cap requirement id such as `billing.update`. */
  readonly requirements?: { readonly [K in Id]: Requirement } | undefined
  /** The requirement deny by default applies; AAL2 when absent. Below AAL2 is a deviation. */
  readonly defaultRequirement?: Requirement | undefined
  /** Turns on email sign-in codes and magic links: a deviation that adds no assurance. */
  readonly emailSignIn?: boolean | undefined
  /** Session limits; a limit longer than ADR 0006 sets is a deviation. */
  readonly timeouts?: Partial<SessionTimeouts> | undefined
  /** The identity providers whose upstream context may count, up to AAL2. */
  readonly trust?: TrustConfig | undefined
}

/** One step-up a session completed. */
export interface StepUpRecord {
  /** When the step-up ceremony completed. */
  readonly at: number
  /** The method that completed it. */
  readonly method: AuthenticationMethod
}

/** The session states `require` distinguishes (ADR 0005 §7, ADR 0007). */
export type SessionKind = "authenticated" | "pre-auth" | "recovery-only"

/** What the session store holds about one session; never a stored level. */
export interface SessionState {
  /** The account the session belongs to. */
  readonly subject: string
  /** The session's state. */
  readonly state: SessionKind
  /** The newest evidence of each (method, authenticator) the session gathered, valid or not (ADR 0005 §2). */
  readonly evidence: readonly AuthenticationEvidence[]
  /** The newest step-up of each method the session completed, oldest first (ADR 0005 §2). */
  readonly stepUps: readonly StepUpRecord[]
  /** When the session entered its state; the absolute limit counts from here. */
  readonly startedAt: number
  /** The last request the session served; the idle limit counts from here. */
  readonly lastSeenAt: number
}

/** A session's assurance, recomputed from the evidence still valid on every read (ADR 0005 §2). */
export interface SessionAssurance {
  /** The level the valid evidence supports; `null` when none is valid. */
  readonly level: AssuranceLevel | null
  /** The evidence still valid. */
  readonly evidence: readonly AuthenticationEvidence[]
  /** The latest time from which the evidence still proves multiple factors; `null` when it does not. */
  readonly lastMultiFactorAt: number | null
  /** The last phishing-resistant ceremony test-cap ran; `null` for none. */
  readonly lastPhishingResistantAt: number | null
  /** The newest step-up of each method the session completed. */
  readonly stepUps: readonly StepUpRecord[]
  /** The version of the policy that computed this. */
  readonly policyVersion: string
  /** When the session ends unless it serves a request first. */
  readonly idleExpiresAt: number
  /** When the session ends whatever it does. */
  readonly absoluteExpiresAt: number
}

/** One thing a `step-up` asks for. */
export type MissingEvidence =
  | {
      /** A higher level. */
      readonly kind: "level"
      /** The level the requirement needs. */
      readonly level: AssuranceLevel
    }
  | {
      /** Phishing-resistant evidence, such as a passkey. */
      readonly kind: "phishing-resistance"
    }
  | {
      /** Evidence of multiple factors fresher than `withinMs`. */
      readonly kind: "fresh-multi-factor"
      /** How recent, in milliseconds, it must be. */
      readonly withinMs: number
    }
  | {
      /** A phishing-resistant ceremony fresher than `withinMs`. */
      readonly kind: "fresh-phishing-resistance"
      /** How recent, in milliseconds, it must be. */
      readonly withinMs: number
    }

/** The answer of `require`: exactly one of five outcomes (ADR 0005 §7). */
export type RequireResult =
  | {
      /** The session meets the requirement. */
      readonly outcome: "allow"
      /** The account the session belongs to. */
      readonly subject: string
      /** The session's assurance, as computed for this answer. */
      readonly assurance: SessionAssurance
    }
  | {
      /** A session exists, but its assurance falls short. */
      readonly outcome: "step-up"
      /** The account the session belongs to. */
      readonly subject: string
      /** What a step-up must add. */
      readonly missing: readonly MissingEvidence[]
      /** The session's assurance, as computed for this answer. */
      readonly assurance: SessionAssurance
    }
  | {
      /** The session is in the pre-auth state: MFA is not set up yet. */
      readonly outcome: "enroll"
    }
  | {
      /** The session came from recovery and may only restore authenticators. */
      readonly outcome: "recovery-only"
    }
  | {
      /** No valid session. */
      readonly outcome: "unauthenticated"
    }

/** A validated policy. `Id` is the union of its requirement ids. */
export interface AuthPolicy<Id extends string> {
  /** The policy version. */
  readonly version: string
  /** Every relaxation of a strict default, for the policy report. */
  readonly deviations: readonly Deviation[]
  /** The session limits in force. */
  readonly timeouts: SessionTimeouts
  /** The trust config in force. */
  readonly trust: TrustConfig
  /** The requirement under `id`; throws on an id the policy does not define. */
  requirement(id: Id): Requirement
  /** The session's assurance at `now`, or `null` when the session has passed a limit. */
  assurance(session: SessionState, now: number): SessionAssurance | null
  /** Whether the session's assurance meets the requirement under `id`, as one of five outcomes. */
  require(session: SessionState | null, id: Id, now: number): RequireResult
}

const LEVELS: ReadonlySet<string> = new Set(["AAL1", "AAL2", "AAL3"])
const FEDERATED_LEVELS: ReadonlySet<string> = new Set(["AAL1", "AAL2"])
const REQUIREMENT_ID = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*$/

const isWhole = (value: number): boolean => Number.isSafeInteger(value) && value >= 1

function requirementProblems(id: string, requirement: Requirement): string[] {
  const problems: string[] = []
  if (!LEVELS.has(requirement.level))
    problems.push(`Requirement "${id}" names an unknown level "${requirement.level}".`)
  for (const field of ["multiFactorWithinMs", "phishingResistantWithinMs"] as const) {
    const value = requirement[field]
    if (value !== undefined && !isWhole(value))
      problems.push(
        `Requirement "${id}" has a ${field} that is not a whole number of at least 1 ms.`,
      )
  }
  return problems
}

function trustProblems(trust: TrustConfig): string[] {
  const problems: string[] = []
  const seen = new Set<string>()
  for (const entry of trust) {
    for (const field of ["acr", "amr"] as const) {
      for (const [value, level] of Object.entries(entry[field] ?? {})) {
        if (!FEDERATED_LEVELS.has(level)) {
          problems.push(
            `The trust config maps ${field} "${value}" of ${entry.issuer} to ${level}; federated evidence stops at AAL2.`,
          )
        }
      }
    }
    if (entry.issuer === "") problems.push("A trusted issuer needs a non-empty issuer.")
    if (!isWhole(entry.maxAuthAgeMs)) {
      problems.push(
        `The maximum authentication age of ${entry.issuer} must be a whole number of at least 1 ms.`,
      )
    }
    if (seen.has(entry.issuer)) problems.push(`The trust config names ${entry.issuer} twice.`)
    seen.add(entry.issuer)
  }
  return problems
}

/**
 * Validates a policy and returns it. Throws a `ConfigError` listing every problem: an empty version, a malformed or
 * reserved requirement id, an unknown level, a bad time limit, or a trust config that maps anything to AAL3.
 */
export function defineAuthPolicy<const Id extends string = never>(
  input: AuthPolicyInput<Id>,
): AuthPolicy<Id | "default"> {
  const problems: string[] = []
  if (input.version === "") problems.push("The policy version must be a non-empty string.")
  const defaultRequirement = input.defaultRequirement ?? { level: "AAL2" }
  const requirements = new Map<string, Requirement>()
  for (const [id, requirement] of Object.entries<Requirement>(input.requirements ?? {})) {
    if (id === "default") {
      problems.push('Requirement id "default" is reserved for the default requirement.')
      continue
    }
    if (!REQUIREMENT_ID.test(id)) {
      problems.push(
        `Requirement id "${id}" must be lowercase words joined by dots, such as billing.update.`,
      )
    }
    problems.push(...requirementProblems(id, requirement))
    requirements.set(id, requirement)
  }
  problems.push(...requirementProblems("default", defaultRequirement))
  requirements.set("default", defaultRequirement)

  const timeouts: SessionTimeouts = { ...DEFAULT_TIMEOUTS, ...input.timeouts }
  const deviations: Deviation[] = []
  if (input.emailSignIn === true) {
    deviations.push({
      kind: "email-sign-in",
      detail: "Email sign-in codes and magic links are on; they add no assurance (ADR 0005).",
    })
  }
  if (!atLeast(defaultRequirement.level, "AAL2")) {
    deviations.push({
      kind: "default-below-aal2",
      detail: `The default requirement is ${defaultRequirement.level}, below AAL2.`,
    })
  }
  for (const [name, value] of Object.entries(timeouts) as [keyof SessionTimeouts, number][]) {
    if (!isWhole(value)) problems.push(`Timeout ${name} must be a whole number of at least 1 ms.`)
    else if (value > DEFAULT_TIMEOUTS[name]) {
      deviations.push({
        kind: "timeout-lengthened",
        detail: `${name} is ${value} ms, longer than the ADR 0006 limit of ${DEFAULT_TIMEOUTS[name]} ms.`,
      })
    }
  }
  const trust = input.trust ?? []
  problems.push(...trustProblems(trust))
  if (problems.length > 0) throw new ConfigError(problems)

  const requirement = (id: string): Requirement => {
    const found = requirements.get(id)
    if (found === undefined) throw new Error(`Unknown requirement id "${id}".`)
    return found
  }

  const assurance = (session: SessionState, now: number): SessionAssurance | null => {
    const restricted = session.state !== "authenticated"
    const idleMs = restricted ? timeouts.restrictedIdleMs : timeouts.aal2IdleMs
    const absoluteMs = restricted ? timeouts.restrictedAbsoluteMs : timeouts.aal2AbsoluteMs
    const idleExpiresAt = session.lastSeenAt + idleMs
    const absoluteExpiresAt = session.startedAt + absoluteMs
    if (now >= idleExpiresAt || now >= absoluteExpiresAt) return null
    const valid = session.evidence.filter(
      (item) => item.at <= now && now < item.at + timeouts.aal2AbsoluteMs,
    )
    const aal3After =
      now < session.lastSeenAt + timeouts.aal3IdleMs ? now - timeouts.aal3AbsoluteMs : Infinity
    const context = { now, trust, aal3After }
    return {
      level: levelOf(valid, context),
      evidence: valid,
      ...recency(valid, context),
      stepUps: session.stepUps,
      policyVersion: input.version,
      idleExpiresAt,
      absoluteExpiresAt,
    }
  }

  return {
    version: input.version,
    deviations,
    timeouts,
    trust,
    requirement,
    assurance,
    require(session, id, now) {
      const needed = requirement(id)
      if (session === null) return { outcome: "unauthenticated" }
      const current = assurance(session, now)
      if (current === null) return { outcome: "unauthenticated" }
      if (session.state === "pre-auth") return { outcome: "enroll" }
      if (session.state === "recovery-only") return { outcome: "recovery-only" }
      if (current.level === null) return { outcome: "unauthenticated" }
      const missing: MissingEvidence[] = []
      if (!atLeast(current.level, needed.level))
        missing.push({ kind: "level", level: needed.level })
      if (needed.phishingResistant === true && current.lastPhishingResistantAt === null)
        missing.push({ kind: "phishing-resistance" })
      const fresh = (at: number | null, withinMs: number | undefined): boolean =>
        withinMs === undefined || now < (at ?? -Infinity) + withinMs
      if (!fresh(current.lastMultiFactorAt, needed.multiFactorWithinMs))
        missing.push({ kind: "fresh-multi-factor", withinMs: needed.multiFactorWithinMs as number })
      if (!fresh(current.lastPhishingResistantAt, needed.phishingResistantWithinMs)) {
        missing.push({
          kind: "fresh-phishing-resistance",
          withinMs: needed.phishingResistantWithinMs as number,
        })
      }
      if (missing.length === 0)
        return { outcome: "allow", subject: session.subject, assurance: current }
      return { outcome: "step-up", subject: session.subject, missing, assurance: current }
    },
  }
}
