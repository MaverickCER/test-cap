/**
 * test-cap/next: the Next.js App Router adapter (Next.js 16), built on test-cap/fetch (ADR 0024 §4). It has three
 * surfaces, and only the second protects anything:
 *
 * - `nextAuthHandler(auth)` is the route handler for `app/auth/[...path]/route.ts`: it serves every `/auth/*` route.
 * - `nextServerAuth(auth, { headers })` is the authoritative check. Call it inside every route handler, server
 *   function and data-access function that needs a session, as close to the data as the app can.
 * - `nextProxy(auth, { public })` is an optional `proxy` that sends a visitor without a session cookie to the sign-in
 *   page early. It is not protection. Next.js's own guide says a proxy "should not be your only line of defense in
 *   protecting your data": it passes any request that carries a session cookie, forged or not, and a route the
 *   proxy's matcher misses never meets it.
 *
 * Next.js has no global check that covers every route, so a route handler or server function that never calls a
 * server helper is unprotected (ADR 0024, Limits). Next.js is typed structurally: this entry has no dependency on it.
 * Next.js gives a route handler no socket address, so the core sees none here; the address is never read from a
 * header (ADR 0009).
 * @packageDocumentation
 */

/**
 * What one successful ceremony proves, recorded as data (ADR 0005 §1). Methods produce `AuthenticationEvidence`;
 * the assurance model computes a session's level from the evidence still valid and never from a stored level.
 */
/** A NIST SP 800-63B-4 authenticator assurance level. */
declare type AssuranceLevel = "AAL1" | "AAL2" | "AAL3";

/** What `createAuth` returns (ADR 0003 §6). */
declare interface Auth<Id extends string = "default"> {
    /** Serves every `/auth/*` route; `null` for a path outside them, so the adapter passes the request on. */
    handle(req: PlainRequest): Promise<PlainResponse | null>;
    /** The request's session, read from the store; `null` when it has none, or it is revoked or expired. */
    session(req: PlainRequest): Promise<SessionInfo | null>;
    /** Whether the request's session meets the requirement under `requirementId`, as one of five outcomes. */
    require(req: PlainRequest, requirementId: Id): Promise<RequireResult>;
    /** The server-side calls. */
    readonly admin: AuthAdmin;
}

/** The server-side calls (ADR 0012, ADR 0014). Phase 3 has `revoke`. */
declare interface AuthAdmin {
    /** Revokes every session of the account, with immediate visibility; resolves to how many it revoked. */
    revoke(subject: string): Promise<number>;
}

/** What one successful ceremony proves. A failed ceremony produces none. */
declare interface AuthenticationEvidence {
    /** The method whose ceremony produced this evidence. */
    readonly method: AuthenticationMethod;
    /** The id of the authenticator used, so its own expiry and failure counters can be found. */
    readonly authenticatorId: string;
    /** The factors this one ceremony proved; a passkey with user verification proves two. */
    readonly factors: readonly Factor[];
    /** True when the ceremony is bound to the origin, so a phishing site cannot relay it. */
    readonly phishingResistant: boolean;
    /** True when a captured response cannot be used again. */
    readonly replayResistant: boolean;
    /** How the key behind a possession factor is held; `unknown` for knowledge factors and federation. */
    readonly keyProtection: KeyProtection;
    /** Whether the authenticator verified the person (PIN or biometric) during this ceremony. */
    readonly userVerified: boolean;
    /** Whether attestation was verified to a trusted root during registration. */
    readonly attestationVerified: boolean;
    /** When the ceremony completed, in milliseconds since the epoch, from the injected clock. */
    readonly at: number;
    /** For federation only: the issuer and the upstream authentication context it reported. */
    readonly federation?: {
        /** The issuer that authenticated the person, as listed in the trust config. */
        readonly issuer: string;
        /** The authentication context class the issuer reported, or `null` when it sent none. */
        readonly acr: string | null;
        /** The authentication methods the issuer reported, as sent. */
        readonly amr: readonly string[];
        /**
         * When the person authenticated at the issuer (OIDC `auth_time`, SAML `AuthnInstant`), in milliseconds since the
         * epoch. A trusted issuer's maximum authentication age runs from it, never from `at`.
         */
        readonly authTime: number;
    };
}

/** The methods that produce evidence. Email sign-in and recovery codes produce none (ADR 0005 §5, ADR 0007). */
declare type AuthenticationMethod = "password" | "totp" | "passkey" | "recovery-code" | "oidc" | "saml";

/** The kinds of proof an authenticator gives. */
declare type Factor = "knowledge" | "possession" | "inherence";

/** How the key behind a possession factor is held: `non-exportable` is required for AAL3 (ADR 0005 §3). */
declare type KeyProtection = "non-exportable" | "syncable" | "unknown";

/** One thing a `step-up` asks for. */
declare type MissingEvidence = {
    /** A higher level. */
    readonly kind: "level";
    /** The level the requirement needs. */
    readonly level: AssuranceLevel;
} | {
    /** Phishing-resistant evidence, such as a passkey. */
    readonly kind: "phishing-resistance";
} | {
    /** Evidence of multiple factors fresher than `withinMs`. */
    readonly kind: "fresh-multi-factor";
    /** How recent, in milliseconds, it must be. */
    readonly withinMs: number;
} | {
    /** A phishing-resistant ceremony fresher than `withinMs`. */
    readonly kind: "fresh-phishing-resistance";
    /** How recent, in milliseconds, it must be. */
    readonly withinMs: number;
};

/**
 * The route handler for `app/auth/[...path]/route.ts`. Mounted anywhere else, every request is a 404, because the
 * core serves only paths under `/auth/`.
 */
export declare function nextAuthHandler(auth: Auth<string>): NextAuthHandlers;

/** What `nextAuthHandler` returns: `export const { GET, POST } = nextAuthHandler(auth)`. */
export declare interface NextAuthHandlers {
    /** Serves the reading routes, such as `/auth/session`. */
    readonly GET: NextRouteHandler;
    /** Serves the state-changing routes, such as `/auth/sign-in`. */
    readonly POST: NextRouteHandler;
}

/** The request headers Next.js's `headers()` from `next/headers` returns. */
export declare type NextHeaders = Iterable<readonly [string, string]>;

/** A Next.js `proxy` function: a response ends the request, `undefined` lets it continue. */
export declare type NextProxy = (req: Request) => Response | undefined;

/**
 * An optional Next.js `proxy` for early redirects only. It is not protection: Next.js's guide says a proxy "should
 * not be your only line of defense in protecting your data". It never reads the store: a visitor whose request
 * carries no session cookie, on a path that is not public, is redirected to the sign-in path; every other request
 * continues, and the server helpers decide. A malformed public list or sign-in path throws a `ConfigError` here.
 *
 * ```ts
 * // proxy.ts
 * export const proxy = nextProxy(auth, { public: ["/"] })
 * ```
 */
export declare function nextProxy(auth: Auth<string>, options?: NextProxyOptions): NextProxy;

/** What `nextProxy` takes. */
export declare interface NextProxyOptions {
    /** The paths a visitor without a session cookie may reach; the same form as `withAuth`'s `public` list. */
    readonly public?: readonly string[] | undefined;
    /**
     * The path on `APP_ORIGIN` a visitor without a session cookie is sent to, with `returnTo`; `/auth/sign-in` when
     * absent.
     */
    readonly signIn?: string | undefined;
}

/** A route handler for one HTTP method, as a `route.ts` file exports it. */
export declare type NextRouteHandler = (req: Request) => Promise<Response>;

/** The server helpers. Each call reads the current request's headers and the session from the store. */
export declare interface NextServerAuth<Id extends string> {
    /** The current request's session; `null` when it has none, or it is revoked or expired. */
    session(): Promise<SessionInfo | null>;
    /**
     * Whether the current request's session meets the requirement (the default requirement when none is named), as
     * one of the five outcomes. Act on anything but `allow` before touching the data. A store failure rejects; it is
     * never an `allow`.
     */
    require(requirementId?: Id | "default"): Promise<RequireResult>;
}

/**
 * The authoritative check for route handlers, server functions and the app's data-access layer:
 *
 * ```ts
 * import { headers } from "next/headers"
 * export const serverAuth = nextServerAuth(auth, { headers })
 * ```
 */
export declare function nextServerAuth<Id extends string>(auth: Auth<Id>, options: NextServerAuthOptions): NextServerAuth<Id>;

/** What `nextServerAuth` takes. */
export declare interface NextServerAuthOptions {
    /** Next.js's `headers` function from `next/headers`, passed in so this entry needs no dependency on Next.js. */
    readonly headers: () => Promise<NextHeaders>;
}

/**
 * The byte transport contract between adapters and the core (ADR 0003). Adapters convert their framework's request
 * into a `PlainRequest` and write the `PlainResponse` back; they parse nothing.
 */
/** A request as bytes. */
declare interface PlainRequest {
    /** The HTTP method exactly as received, such as `POST`. */
    readonly method: string;
    /** Absolute (scheme, host, path and query) or origin-form (`/path?query`), exactly as received. */
    readonly url: string;
    /** Repeated headers keep every value. */
    readonly headers: Headers;
    /** The raw body, or `null` when there is none. */
    readonly body: Uint8Array | null;
    /** The socket's peer address. Never a forwarded header (ADR 0009). */
    readonly clientAddress?: string | undefined;
    /** Aborts when the client goes away; the core stops before its next store write. */
    readonly signal?: AbortSignal | undefined;
}

/** A response as bytes. Each `Set-Cookie` value stays separate (`headers.getSetCookie()`). */
declare interface PlainResponse {
    /** The HTTP status code. */
    readonly status: number;
    /** The response headers; the adapter writes each `Set-Cookie` value as its own header line. */
    readonly headers: Headers;
    /** The raw body, or `null` when there is none. */
    readonly body: Uint8Array | null;
}

/** The answer of `require`: exactly one of five outcomes (ADR 0005 §7). */
declare type RequireResult = {
    /** The session meets the requirement. */
    readonly outcome: "allow";
    /** The account the session belongs to. */
    readonly subject: string;
    /** The session's assurance, as computed for this answer. */
    readonly assurance: SessionAssurance;
} | {
    /** A session exists, but its assurance falls short. */
    readonly outcome: "step-up";
    /** The account the session belongs to. */
    readonly subject: string;
    /** What a step-up must add. */
    readonly missing: readonly MissingEvidence[];
    /** The session's assurance, as computed for this answer. */
    readonly assurance: SessionAssurance;
} | {
    /** The session is in the pre-auth state: MFA is not set up yet. */
    readonly outcome: "enroll";
} | {
    /** The session came from recovery and may only restore authenticators. */
    readonly outcome: "recovery-only";
} | {
    /** No valid session. */
    readonly outcome: "unauthenticated";
};

/** A session's assurance, recomputed from the evidence still valid on every read (ADR 0005 §2). */
declare interface SessionAssurance {
    /** The level the valid evidence supports; `null` when none is valid. */
    readonly level: AssuranceLevel | null;
    /** The evidence still valid. */
    readonly evidence: readonly AuthenticationEvidence[];
    /** The latest time from which the evidence still proves multiple factors; `null` when it does not. */
    readonly lastMultiFactorAt: number | null;
    /** The last phishing-resistant ceremony test-cap ran; `null` for none. */
    readonly lastPhishingResistantAt: number | null;
    /** The newest step-up of each method the session completed. */
    readonly stepUps: readonly StepUpRecord[];
    /** The version of the policy that computed this. */
    readonly policyVersion: string;
    /** When the session ends unless it serves a request first. */
    readonly idleExpiresAt: number;
    /** When the session ends whatever it does. */
    readonly absoluteExpiresAt: number;
}

/** A session as the session endpoint reports it (ADR 0006): what it is, never its token. */
declare interface SessionInfo {
    /** The session's public id, the one the session list and remote revoke use. */
    readonly id: string;
    /** The account it belongs to. */
    readonly subject: string;
    /** `authenticated`, or `pre-auth` while MFA is not yet set up, or `recovery-only`. */
    readonly state: "authenticated" | "pre-auth" | "recovery-only";
    /** The level its still-valid evidence supports; `null` when none does. */
    readonly level: "AAL1" | "AAL2" | "AAL3" | null;
    /** The methods of its still-valid evidence. */
    readonly methods: readonly AuthenticationMethod[];
    /** When the session ends unless it serves a request first (epoch ms). */
    readonly idleExpiresAt: number;
    /** When the session ends whatever it does (epoch ms). */
    readonly absoluteExpiresAt: number;
}

/** One step-up a session completed. */
declare interface StepUpRecord {
    /** When the step-up ceremony completed. */
    readonly at: number;
    /** The method that completed it. */
    readonly method: AuthenticationMethod;
}

export { }
