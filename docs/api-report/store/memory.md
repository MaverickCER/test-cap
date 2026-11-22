# store/memory

`test-cap/store/memory`: the reference store, for development and tests only (ADR 0002). It passes the conformance
kit within one process, but it keeps nothing across restarts and nothing between processes, so it declares itself
non-durable and production refuses it (ADR 0026).

Every operation runs under one lock, so each is atomic and a transaction's partial state is never visible.

## Functions

### memoryStore()

```ts
function memoryStore(): AuthStore & {
  transaction: <T>(fn) => Promise<T>;
};
```

The in-memory reference store. Development and tests only.

#### Returns
