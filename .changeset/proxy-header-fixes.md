---
"test-cap": patch
---

A bracketed IPv6 hop with no port, such as `[2001:db8::7]`, is read as its address. It used to be cut at its last colon.
A hop that is no address at all is read as `unknown`.

The `forwarded-header-ignored` diagnostic changes in three ways:

- it no longer fires when a platform's own header was read beside `X-Forwarded-For`;
- when a peer outside a preset's ranges sends the preset's own header, that header is the one it names;
- a request with no socket address is named as such, not as "undefined".
