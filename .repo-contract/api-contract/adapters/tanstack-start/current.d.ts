/**
 * test-cap/tanstack-start: the TanStack Start adapter (ADR 0024). It converts and decides nothing:
 *
 * - `tanstackStartMiddleware(auth, { public })` is the server function of a global request middleware. TanStack
 *   Start runs it for every request, pages, server routes and server function calls alike. It sends the request's
 *   head to the core's gate, which refuses an ambiguous path with a 400 and applies deny by default with the public
 *   list; a refusal is answered here, and every other request continues with `context.auth` set.
 * - `tanstackStartAuth(auth).handlers` serves the `/auth/$` server route: the body is read here, once, as bytes, and
 *   goes to `auth.handle`.
 * - `tanstackStartAuth(auth).require` and `.session` let a server function check a requirement itself, close to the
 *   data, and answer with the core's outcome.
 *
 * TanStack Start is typed structurally, so this entry has no dependency on it.
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

/** What `tanstackStartAuth` returns. */
export declare interface TanstackStartAuth<Id extends string> {
    /** The `/auth/$` server route's handlers. */
    readonly handlers: TanstackStartRouteHandlers;
    /** The request's session, read from the store; `null` when it has none, or it is revoked or expired. */
    session(request: Request): Promise<SessionInfo | null>;
    /** Whether the request's session meets the requirement under `requirementId`, as one of five outcomes. */
    require(request: Request, requirementId: Id): Promise<RequireResult>;
}

/**
 * The `/auth/$` server route and the server helpers. Serve the route with
 * `server: { handlers: tanstackStartAuth(auth).handlers }`.
 */
export declare function tanstackStartAuth<Id extends string>(auth: Auth<Id>): TanstackStartAuth<Id>;

/** What `context.auth` holds: the subject on a protected route, `null` on a public one and under `/auth/`. */
export declare type TanstackStartAuthInfo = {
    /** The account the request's session belongs to. */
    readonly subject: string;
} | null;

/** The context the middleware adds for the routes and server functions after it. */
export declare interface TanstackStartContext {
    /** The subject deny by default let through, or `null`. */
    readonly auth: TanstackStartAuthInfo;
}

/** The server function of a request middleware: a refusal as a `Response`, or whatever `next` answered. */
export declare type TanstackStartMiddleware = <Next>(input: TanstackStartMiddlewareInput<Next>) => Promise<Awaited<Next> | Response>;

/**
 * The global request middleware's server function: protects every route and server function at the default
 * requirement unless `options.public` lists its path. Register it with
 * `createStart(() => ({ requestMiddleware: [createMiddleware().server(tanstackStartMiddleware(auth, options))] }))`.
 */
export declare function tanstackStartMiddleware(auth: Auth<string>, options?: TanstackStartMiddlewareOptions): TanstackStartMiddleware;

/** The parts of TanStack Start's request middleware options the adapter reads. */
export declare interface TanstackStartMiddlewareInput<Next> {
    /** The request as TanStack Start received it. */
    readonly request: Request;
    /** Continues to the next middleware, the route or the server function, with the adapter's context added. */
    readonly next: (options: {
        context: TanstackStartContext;
    }) => Next;
}

/** What `tanstackStartMiddleware` takes. */
export declare interface TanstackStartMiddlewareOptions {
    /**
     * The paths that need no session. An entry matches exactly (`"/"` is the root only), or ends in `/*` to match one or
     * more segments below it (`"/blog/*"`). Matching is case-sensitive. Everything else needs the default requirement,
     * server function calls included.
     */
    readonly public?: readonly string[] | undefined;
}

/** A server route handler: TanStack Start passes more than the request, and the adapter reads only the request. */
export declare type TanstackStartRouteHandler = (input: {
    /** The request as TanStack Start received it. */
    readonly request: Request;
}) => Promise<Response>;

/** The handlers for the `/auth/$` server route. */
export declare interface TanstackStartRouteHandlers {
    /** Every method: the core answers a method a route does not take with a 405. */
    readonly ANY: TanstackStartRouteHandler;
}

export { }
