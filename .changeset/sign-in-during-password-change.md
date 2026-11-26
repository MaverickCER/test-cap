---
"test-cap": patch
---

A sign-in that checked the old password while the owner replaced it no longer keeps its session. The password change
revoked the account's sessions before that sign-in wrote its own. The sign-in now reads the password again after
writing the session, and a changed or missing password revokes it and answers `401 invalid-credentials`.
