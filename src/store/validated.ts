/**
 * Argument checks for every `AuthStore` operation, in one place. A store wraps its raw operations with `validated`
 * so a malformed call fails before anything reaches the database, with the same message from every store.
 */

import {
  assertJson,
  assertName,
  assertNewRecord,
  assertWhole,
  type StoreOperations,
} from "./port.js"

function key(tenant: string, collection: string, recordKey: string): void {
  assertName(tenant, "The tenant")
  assertName(collection, "The collection")
  assertName(recordKey, "The key")
}

function owned(tenant: string, collection: string, owner: string): void {
  assertName(tenant, "The tenant")
  assertName(collection, "The collection")
  assertName(owner, "The owner")
}

function counter(tenant: string, name: string): void {
  assertName(tenant, "The tenant")
  assertName(name, "The counter")
}

function stream(tenant: string, name: string): void {
  assertName(tenant, "The tenant")
  assertName(name, "The stream")
}

/** `ops` with every argument checked first. Checks throw `TypeError` or `RangeError` and never call `ops`. */
export function validated(ops: StoreOperations): StoreOperations {
  return {
    async createUnique(tenant, record) {
      assertName(tenant, "The tenant")
      assertNewRecord(record)
      return ops.createUnique(tenant, record)
    },
    async get(tenant, collection, recordKey) {
      key(tenant, collection, recordKey)
      return ops.get(tenant, collection, recordKey)
    },
    async listByOwner(tenant, collection, owner) {
      owned(tenant, collection, owner)
      return ops.listByOwner(tenant, collection, owner)
    },
    async update(tenant, collection, recordKey, expectedVersion, change) {
      key(tenant, collection, recordKey)
      assertWhole(expectedVersion, "The expected version", 1)
      if (change.data !== undefined) assertJson(change.data)
      if (change.expiresAt !== undefined && change.expiresAt !== null)
        assertWhole(change.expiresAt, "expiresAt")
      return ops.update(tenant, collection, recordKey, expectedVersion, change)
    },
    async revoke(tenant, collection, recordKey, at) {
      key(tenant, collection, recordKey)
      assertWhole(at, "The revocation time")
      return ops.revoke(tenant, collection, recordKey, at)
    },
    async revokeByOwner(tenant, collection, owner, at, options) {
      owned(tenant, collection, owner)
      assertWhole(at, "The revocation time")
      return ops.revokeByOwner(tenant, collection, owner, at, options)
    },
    async delete(tenant, collection, recordKey) {
      key(tenant, collection, recordKey)
      return ops.delete(tenant, collection, recordKey)
    },
    async consumeOnce(tenant, collection, recordKey, now) {
      key(tenant, collection, recordKey)
      assertWhole(now, "The time")
      return ops.consumeOnce(tenant, collection, recordKey, now)
    },
    async increment(tenant, name, windowMs, now) {
      counter(tenant, name)
      assertWhole(windowMs, "The window", 1)
      assertWhole(now, "The time")
      return ops.increment(tenant, name, windowMs, now)
    },
    async resetCounter(tenant, name) {
      counter(tenant, name)
      return ops.resetCounter(tenant, name)
    },
    async appendAudit(tenant, name, seq, record) {
      stream(tenant, name)
      assertWhole(seq, "The sequence number", 1)
      assertJson(record, "record")
      return ops.appendAudit(tenant, name, seq, record)
    },
    async readAudit(tenant, name, fromSeq, limit) {
      stream(tenant, name)
      assertWhole(fromSeq, "The first sequence number", 1)
      assertWhole(limit, "The limit", 1)
      return ops.readAudit(tenant, name, fromSeq, limit)
    },
  }
}
