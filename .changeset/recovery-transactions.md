---
"test-cap": minor
---

Hold recovery codes and email codes to single transactions and to the code they belong to (ADR 0007, ADR 0021).

- **One live set of recovery codes per account.** A new set becomes current by one compare-and-set, so of two
  parallel requests exactly one wins, and the old set keeps working until the switch.
- **Redeeming a code and the recovery password change run in one transaction** where the store has them, so a
  failure leaves a code unspent and a password unchanged.
- **Email-code attempts count against the newest code only.** A new code starts at zero attempts.
- **test-cap's store conformance tests have two more checks**, `transaction-rolls-back-single-use` and
  `transaction-consume-once-concurrent`, which the memory store and the SQL store (on SQLite and PGlite)
  pass.
