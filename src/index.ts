/**
 * test-cap: the internal authentication package for MaverickCER apps.
 *
 * This entry holds `createAuth` and the policy that configures it (phase 3), and the foundation's public contract
 * (phase 2): the byte transport an adapter speaks, the store port an app implements, the injected clock and random
 * source, the deployment modes, and the two error types. Adapters live in their own entries, such as
 * `test-cap/express`.
 * @packageDocumentation
 */

export { createAuth } from "./core/auth.js"
export type {
  Auth,
  AuthAdmin,
  AuthConfig,
  EmailMessage,
  SendEmail,
  SessionInfo,
  TrustedProxies,
} from "./core/auth.js"
export { defineAuthPolicy } from "./assurance/policy.js"
export type {
  AuthPolicy,
  AuthPolicyInput,
  Deviation,
  MissingEvidence,
  Requirement,
  RequireResult,
  SessionAssurance,
  SessionKind,
  SessionState,
  SessionTimeouts,
  StepUpRecord,
} from "./assurance/policy.js"
export type { FederatedLevel, TrustConfig, TrustedIssuer } from "./assurance/levels.js"
export type { HibpFetch, HibpResponse } from "./methods/password/hibp.js"
export type { Argon2Cost } from "./methods/password/argon2.js"

export type {
  AssuranceLevel,
  AuthenticationEvidence,
  AuthenticationMethod,
  Factor,
  KeyProtection,
} from "./assurance/evidence.js"
export type { Clock, RandomSource } from "./core/clock.js"
export { ConfigError, TransportError } from "./core/errors.js"
export type { TransportErrorCode } from "./core/errors.js"
export type { DeploymentMode, StoreTraits } from "./core/mode.js"
export type {
  AuditEntry,
  AuthStore,
  CounterState,
  JsonValue,
  NewRecord,
  RecordChange,
  StoredRecord,
  StoreOperations,
  StoreTransaction,
  TenantId,
} from "./store/port.js"
export type {
  SqlDialect,
  SqlParam,
  SqlQuery,
  SqlResult,
  SqlStoreOptions,
  SqlTransaction,
} from "./store/sql.js"
export type { PlainRequest, PlainResponse } from "./transport/types.js"
export type {
  ConformanceOptions,
  ConformanceReport,
  ConformanceResult,
} from "./conformance/index.js"
export type {
  AuthenticationActivity,
  AuthenticationEvent,
  AuthenticationInput,
  EventInput,
  EventSink,
  EventSubject,
  FactorKind,
  OcsfActor,
  OcsfAuthFactor,
  OcsfBaseEvent,
  OcsfMetadata,
  OcsfProduct,
  OcsfService,
  OcsfSession,
  OcsfUnmapped,
  OcsfUser,
  Outcome,
  SecurityEvent,
  SessionRef,
  TestCapFacts,
  UserManagementActivity,
  UserManagementEvent,
  UserManagementInput,
} from "./ocsf/events.js"
export type {
  FieldLength,
  FieldList,
  FieldPattern,
  FieldState,
  FlowOutcome,
  FormId,
  FormModel,
  FormOptions,
  Messages,
} from "./forms/model.js"
export type { PageAssets, PageContext, PageLink } from "./pages/render.js"
export type { PageAsset, PageAssetSet } from "./pages/assets.js"
