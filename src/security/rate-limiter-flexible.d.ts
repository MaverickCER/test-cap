// rate-limiter-flexible is imported by deep path only: its index requires every store it ships, including one that
// loads Node's `cluster` (ADR 0030). These declarations give each deep path the type its package already publishes.
declare module "rate-limiter-flexible/lib/RateLimiterStoreAbstract.js" {
  import { RateLimiterStoreAbstract } from "rate-limiter-flexible"
  export default RateLimiterStoreAbstract
}

declare module "rate-limiter-flexible/lib/RateLimiterRes.js" {
  import { RateLimiterRes } from "rate-limiter-flexible"
  export default RateLimiterRes
}

declare module "rate-limiter-flexible/lib/RateLimiterMemory.js" {
  import { RateLimiterMemory } from "rate-limiter-flexible"
  export default RateLimiterMemory
}

declare module "rate-limiter-flexible/lib/RateLimiterUnion.js" {
  import { RateLimiterUnion } from "rate-limiter-flexible"
  export default RateLimiterUnion
}
