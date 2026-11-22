/**
 * The level rules of ADR 0005 §3, as a pure function from the evidence still valid to an assurance level. No method
 * and no configuration declares a level: each rule is a check on what a ceremony proved.
 */

import type { AssuranceLevel, AuthenticationEvidence, Factor } from "./evidence.js"

/** The levels a trust config may map an upstream context to: federated evidence stops at AAL2. */
export type FederatedLevel = "AAL1" | "AAL2"

/** One issuer whose reported authentication context may count, up to AAL2 (ADR 0005 §3). */
export interface TrustedIssuer {
  /** The issuer, exactly as its tokens or assertions name it. */
  readonly issuer: string
  /** Upstream `acr` values and the level each counts as. */
  readonly acr?: Readonly<Record<string, FederatedLevel>> | undefined
  /** Upstream `amr` values and the level each counts as; the highest mapped value wins. */
  readonly amr?: Readonly<Record<string, FederatedLevel>> | undefined
  /** How long after the upstream authentication its mapped level holds, in milliseconds; AAL1 after that. */
  readonly maxAuthAgeMs: number
}

/** The issuers whose upstream context may count. */
export type TrustConfig = readonly TrustedIssuer[]

/** What `levelOf` needs besides the evidence. */
export interface LevelContext {
  /** Epoch milliseconds, from the injected clock. */
  readonly now: number
  /** The trust config; no issuer is trusted when absent. */
  readonly trust?: TrustConfig | undefined
  /** Evidence counts towards AAL3 only when it completed after this time; absent for no limit. */
  readonly aal3After?: number | undefined
}

const RANK: Readonly<Record<AssuranceLevel, number>> = { AAL1: 1, AAL2: 2, AAL3: 3 }
const NAMES: readonly (AssuranceLevel | null)[] = [null, "AAL1", "AAL2", "AAL3"]
const LOCAL: ReadonlySet<string> = new Set(["password", "totp", "passkey"])
const FEDERATED: ReadonlySet<string> = new Set(["oidc", "saml"])

/** True for evidence from a ceremony test-cap ran itself, not one an identity provider reports. */
export function isLocal(evidence: AuthenticationEvidence): boolean {
  return LOCAL.has(evidence.method)
}

/** True when `level` meets `required`. */
export function atLeast(level: AssuranceLevel, required: AssuranceLevel): boolean {
  return RANK[level] >= RANK[required]
}

/** The factors evidence really proves: a possession authenticator that did not verify the person proves possession. */
function provenFactors(evidence: AuthenticationEvidence): readonly Factor[] {
  if (evidence.factors.includes("possession") && !evidence.userVerified) return ["possession"]
  return evidence.factors
}

function meetsAal3(evidence: AuthenticationEvidence, after: number): boolean {
  return (
    evidence.at > after &&
    new Set(provenFactors(evidence)).size > 1 &&
    evidence.keyProtection === "non-exportable" &&
    evidence.attestationVerified &&
    evidence.userVerified &&
    evidence.phishingResistant
  )
}

/** The rank federated evidence earns: AAL1 unless a trusted issuer maps its context, within its maximum age. */
function federatedRank(evidence: AuthenticationEvidence, context: LevelContext): number {
  const federation = evidence.federation
  if (federation === undefined) return 1
  const issuer = context.trust?.find((entry) => entry.issuer === federation.issuer)
  // The age runs from the upstream authentication; a reported time after local completion cannot be true.
  const authenticatedAt = Math.min(federation.authTime, evidence.at)
  if (issuer === undefined || context.now >= authenticatedAt + issuer.maxAuthAgeMs) return 1
  const ranks = [
    federation.acr === null ? undefined : issuer.acr?.[federation.acr],
    ...federation.amr.map((value) => issuer.amr?.[value]),
  ]
    .filter((level): level is FederatedLevel => level !== undefined)
    .map((level) => RANK[level])
  return Math.max(1, ...ranks)
}

/** What a run of evidence has proved so far: the highest rank one item reached, and the local factors. */
interface Tally {
  rank: number
  readonly factors: Set<Factor>
}

/** Adds one item to the tally. */
function count(tally: Tally, item: AuthenticationEvidence, context: LevelContext): void {
  if (FEDERATED.has(item.method)) tally.rank = Math.max(tally.rank, federatedRank(item, context))
  if (!isLocal(item)) return
  for (const factor of provenFactors(item)) tally.factors.add(factor)
  tally.rank = Math.max(tally.rank, meetsAal3(item, context.aal3After ?? -Infinity) ? 3 : 1)
}

/** The rank (0 for none, 1 to 3 for AAL1 to AAL3) a tally supports: two local factors make at least AAL2. */
function rankOfTally(tally: Tally): number {
  return tally.factors.size > 1 ? Math.max(tally.rank, 2) : tally.rank
}

/** The rank the evidence supports. */
function rankOf(evidence: readonly AuthenticationEvidence[], context: LevelContext): number {
  const tally: Tally = { rank: 0, factors: new Set() }
  for (const item of evidence) count(tally, item, context)
  return rankOfTally(tally)
}

/**
 * The level the evidence supports (ADR 0005 §3), or `null` for none. The caller passes only evidence still valid.
 * Evidence from a method outside test-cap's list, an email link or a recovery code among them, adds nothing.
 */
export function levelOf(
  evidence: readonly AuthenticationEvidence[],
  context: LevelContext,
): AssuranceLevel | null {
  return NAMES[rankOf(evidence, context)] ?? null
}

/** The two times a requirement's recency rules read (ADR 0005 §2). */
export interface Recency {
  /**
   * The latest time from which the evidence alone still proves multiple factors: the latest proof time of an item
   * whose suffix (every item at or after it) proves them. Federated evidence proved its factors at the upstream
   * authentication, so it counts from min(authTime, at), as its maximum age does.
   */
  readonly lastMultiFactorAt: number | null
  /** The last phishing-resistant ceremony test-cap ran itself. */
  readonly lastPhishingResistantAt: number | null
}

/**
 * The recency times of the evidence, in one pass from the newest item back (a suffix scan), so a read costs a sort
 * and a linear scan however much evidence a session holds. Items at the same time are each in the other's suffix.
 */
export function recency(
  evidence: readonly AuthenticationEvidence[],
  context: LevelContext,
): Recency {
  const newestFirst = [...evidence].sort((a, b) => b.at - a.at)
  const tally: Tally = { rank: 0, factors: new Set() }
  // Whether the suffix from each time proves multiple factors; the last item at a time leaves the whole group's answer.
  const proves = new Map<number, boolean>()
  for (const item of newestFirst) {
    count(tally, item, context)
    proves.set(item.at, rankOfTally(tally) >= 2)
  }
  let lastMultiFactorAt: number | null = null
  let lastPhishingResistantAt: number | null = null
  for (const item of newestFirst) {
    if (proves.get(item.at) === true) {
      const provedAt = Math.min(item.federation?.authTime ?? item.at, item.at)
      lastMultiFactorAt = Math.max(lastMultiFactorAt ?? provedAt, provedAt)
    }
    if (isLocal(item) && item.phishingResistant) {
      lastPhishingResistantAt = Math.max(lastPhishingResistantAt ?? item.at, item.at)
    }
  }
  return { lastMultiFactorAt, lastPhishingResistantAt }
}
