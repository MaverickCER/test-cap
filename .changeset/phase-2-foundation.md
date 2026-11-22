---
"test-cap": minor
---

Add the foundation's public contract:

- the `PlainRequest` and `PlainResponse` byte transport types;
- the `AuthStore` port with its record, counter and audit types, and the conformance report types;
- `Clock`, `RandomSource`, `DeploymentMode` and `StoreTraits`;
- the `TransportError` and `ConfigError` classes.

Breaking: the scaffold's placeholder `packageName()` export is removed. While the version is `0.x` this is released
as a minor.
