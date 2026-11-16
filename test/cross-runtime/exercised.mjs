// Every value export of dist/index.js that run.mjs exercises. Its own module, so the coverage test can read the list
// without running the checks (run.mjs exits the process on a failure).
export const EXERCISED = ["ConfigError", "TransportError"]
