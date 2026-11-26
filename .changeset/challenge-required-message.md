---
"test-cap": minor
---

Add `Messages.challengeRequired`. When the app's credential-stuffing challenge refuses a sign-in posted from a default
page, the page now says the sign-in needs an extra check that the page cannot show. Before, it said something went
wrong on the server's side, which was not true.
