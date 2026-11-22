---
"test-cap": minor
---

Add `argon2Cost` to `createAuth`'s config: a lower argon2id cost for test suites, refused in every mode but `test`
(ADR 0018 §1, ADR 0026 §4). Federated evidence now carries `federation.authTime`, the upstream authentication time,
and a trusted issuer's maximum authentication age runs from it rather than from local completion. OIDC sign-in,
which will produce federated evidence, is planned for phase 5.
