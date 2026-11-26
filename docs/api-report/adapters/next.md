# adapters/next

test-cap/next: the Next.js App Router adapter (Next.js 16), built on test-cap/fetch (ADR 0024 §4). It has three
surfaces, and only the second protects anything:

- `nextAuthHandler(auth)` is the route handler for `app/auth/[...path]/route.ts`: it serves every `/auth/*` route.
- `nextServerAuth(auth, { headers })` is the authoritative check. Call it inside every route handler, server
  function and data-access function that needs a session, as close to the data as the app can.
- `nextProxy(auth, { public })` is an optional `proxy` that sends a visitor without a session cookie to the sign-in
  page early. It is not protection. Next.js's own guide says a proxy "should not be your only line of defense in
  protecting your data": it passes any request that carries a session cookie, forged or not, and a route the
  proxy's matcher misses never meets it.

Next.js has no global check that covers every route, so a route handler or server function that never calls a
server helper is unprotected (ADR 0024, Limits). Next.js is typed structurally: this entry has no dependency on it.
Next.js gives a route handler no socket address. The core sees one only from `nextAuthHandler`'s `clientAddress`
option, or reads a platform preset's header (ADR 0009 §5); no other header is ever read.

## Interfaces

### NextAuthHandlerOptions

What `nextAuthHandler` takes.

#### Properties

##### clientAddress?

```ts
readonly optional clientAddress?: (request) => string | undefined;
```

The client's address for the throttle, read from what the app's own server knows, such as a custom server's
socket. Next.js gives a route handler none. Behind a platform preset whose header every request carries, such as
`platform("vercel")`, leave it out: the core reads the preset's header (ADR 0009 §5). Otherwise production and
staging refuse to start without it, unless the app set `requireClientAddress: false` (ADR 0009 §8).

###### Parameters

| Parameter | Type |
| ------ | ------ |
| `request` | `Request` |

###### Returns

`string` \| `undefined`

***

### NextAuthHandlers

What `nextAuthHandler` returns: `export const { GET, POST } = nextAuthHandler(auth)`.

#### Properties

##### GET

```ts
readonly GET: NextRouteHandler;
```

Serves the reading routes, such as `/auth/session`.

##### POST

```ts
readonly POST: NextRouteHandler;
```

Serves the state-changing routes, such as `/auth/sign-in`.

***

### NextProxyOptions

What `nextProxy` takes.

#### Properties

##### public?

```ts
readonly optional public?: readonly string[];
```

The paths a visitor without a session cookie may reach; the same form as `withAuth`'s `public` list.

##### signIn?

```ts
readonly optional signIn?: string;
```

The path a visitor without a session cookie is sent to, with `returnTo`, as the app receives it; `/auth/sign-in`
when absent. Any `publicBasePath` is added before it in the redirect.

***

### NextServerAuth

The server helpers. Each call reads the current request's headers and the session from the store.

#### Type Parameters

| Type Parameter |
| ------ |
| `Id` *extends* `string` |

#### Methods

##### require()

```ts
require(requirementId?): Promise<RequireResult>;
```

Whether the current request's session meets the requirement (the default requirement when none is named), as
one of the five outcomes. Act on anything but `allow` before touching the data. A store failure rejects; it is
never an `allow`.

###### Parameters

| Parameter | Type |
| ------ | ------ |
| `requirementId?` | `"default"` \| `Id` |

###### Returns

`Promise`\<[`RequireResult`](../index.md#requireresult)\>

##### session()

```ts
session(): Promise<SessionInfo | null>;
```

The current request's session; `null` when it has none, or it is revoked or expired.

###### Returns

`Promise`\<[`SessionInfo`](../index.md#sessioninfo) \| `null`\>

***

### NextServerAuthOptions

What `nextServerAuth` takes.

#### Properties

##### headers

```ts
readonly headers: () => Promise<NextHeaders>;
```

Next.js's `headers` function from `next/headers`, passed in so this entry needs no dependency on Next.js.

###### Returns

`Promise`\<[`NextHeaders`](#nextheaders)\>

## Type Aliases

### NextHeaders

```ts
type NextHeaders = Iterable<readonly [string, string]>;
```

The request headers Next.js's `headers()` from `next/headers` returns.

***

### NextProxy

```ts
type NextProxy = (req) => Response | undefined;
```

A Next.js `proxy` function: a response ends the request, `undefined` lets it continue.

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `req` | `Request` |

#### Returns

`Response` \| `undefined`

***

### NextRouteHandler

```ts
type NextRouteHandler = (req) => Promise<Response>;
```

A route handler for one HTTP method, as a `route.ts` file exports it.

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `req` | `Request` |

#### Returns

`Promise`\<`Response`\>

## Functions

### nextAuthHandler()

```ts
function nextAuthHandler(auth, options?): NextAuthHandlers;
```

The route handler for `app/auth/[...path]/route.ts`. Mounted anywhere else, every request is a 404, because the
core serves only paths under `/auth/`.

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `auth` | [`Auth`](../index.md#auth)\<`string`\> |
| `options` | [`NextAuthHandlerOptions`](#nextauthhandleroptions) |

#### Returns

[`NextAuthHandlers`](#nextauthhandlers)

***

### nextProxy()

```ts
function nextProxy(auth, options?): NextProxy;
```

An optional Next.js `proxy` for early redirects only. It is not protection: Next.js's guide says a proxy "should
not be your only line of defense in protecting your data". It never reads the store: a visitor whose request
carries no session cookie, on a path that is not public, is redirected to the sign-in path; every other request
continues, and the server helpers decide. A malformed public list or sign-in path throws a `ConfigError` here.

```ts
// proxy.ts
export const proxy = nextProxy(auth, { public: ["/"] })
```

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `auth` | [`Auth`](../index.md#auth)\<`string`\> |
| `options` | [`NextProxyOptions`](#nextproxyoptions) |

#### Returns

[`NextProxy`](#nextproxy)

***

### nextServerAuth()

```ts
function nextServerAuth<Id>(auth, options): NextServerAuth<Id>;
```

The authoritative check for route handlers, server functions and the app's data-access layer:

```ts
import { headers } from "next/headers"
export const serverAuth = nextServerAuth(auth, { headers })
```

#### Type Parameters

| Type Parameter |
| ------ |
| `Id` *extends* `string` |

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `auth` | [`Auth`](../index.md#auth)\<`Id`\> |
| `options` | [`NextServerAuthOptions`](#nextserverauthoptions) |

#### Returns

[`NextServerAuth`](#nextserverauth)\<`Id`\>
