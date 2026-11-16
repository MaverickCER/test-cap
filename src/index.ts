/**
 * test-cap: the internal authentication package for MaverickCER apps.
 *
 * This entry holds the foundation's public contract (phase 2): the byte transport an adapter speaks, the store port an
 * app implements, the injected clock and random source, the deployment modes, and the two error types. `createAuth`
 * joins it when the first complete slice passes its gate (ADR 0004).
 * @packageDocumentation
 */

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
export type { PlainRequest, PlainResponse } from "./transport/types.js"
export type {
  ConformanceOptions,
  ConformanceReport,
  ConformanceResult,
} from "./conformance/index.js"
