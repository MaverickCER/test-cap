---
"test-cap": patch
---

A step-up checks its challenge before the secret. An expired or foreign challenge spends no TOTP code and touches no
throttle key. The step-up page then shows "This form expired. Enter your code again." instead of a server error.

Making recovery codes while the hashing queue is full answers `503 busy`, as every other hashing route does, not `500`.
