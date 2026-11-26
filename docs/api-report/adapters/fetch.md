# adapters/fetch

test-cap/fetch: the adapter for any runtime whose server hands the app a Web `Request` and takes a `Response` back,
such as `Bun.serve` and `Deno.serve` (ADR 0024). It converts and decides nothing:

- `withAuth(auth, handler, { public })` wraps the app's handler with deny by default: every request first goes to
  the core's gate, which refuses an ambiguous path with a 400; a path under `/auth/` is served by the core; a public
  path reaches the handler with a `null` subject; any other path reaches it only for a session meeting the default
  requirement, with that session's subject.
- `fetchAuth(auth)` serves the `/auth/` routes alone and answers `null` for every other path, for an app that
  routes by itself.

The body of an `/auth/` request is read once, as bytes, and at most one chunk past the core's limit; the body of
every other request is left unread for the app. Every `Set-Cookie` value stays its own header line. The client's
address comes only from the `clientAddress` option, which reads what the runtime hands its handler, never from a
header (ADR 0009).

The runtime has parsed the URL before the adapter sees it, and the app's router reads that same `req.url`, so the
two cannot disagree about the path; the core still refuses any ambiguous path the parsed URL keeps, such as `//`.

## Interfaces

### FetchAuthOptions

What `fetchAuth` takes.

#### Extended by

- [`WithAuthOptions`](#withauthoptions)

#### Type Parameters

| Type Parameter |
| ------ |
| `Args` *extends* `unknown`[] |

#### Properties

##### clientAddress?

```ts
readonly optional clientAddress?: ClientAddress<Args>;
```

Reads the client's address from the runtime's arguments: `(req, info) => info.remoteAddr.hostname` on Deno,
`(req, server) => server.requestIP(req)?.address` on Bun. Without it the core sees no address, and in production
and staging the adapter refuses to start with a `ConfigError`, unless a platform preset reads its header from every
request or the app set `requireClientAddress: false` (ADR 0009 §8).

***

### WithAuthOptions

What `withAuth` takes.

#### Extends

- [`FetchAuthOptions`](#fetchauthoptions)\<`Args`\>

#### Type Parameters

| Type Parameter |
| ------ |
| `Args` *extends* `unknown`[] |

#### Properties

##### clientAddress?

```ts
readonly optional clientAddress?: ClientAddress<Args>;
```

Reads the client's address from the runtime's arguments: `(req, info) => info.remoteAddr.hostname` on Deno,
`(req, server) => server.requestIP(req)?.address` on Bun. Without it the core sees no address, and in production
and staging the adapter refuses to start with a `ConfigError`, unless a platform preset reads its header from every
request or the app set `requireClientAddress: false` (ADR 0009 §8).

###### Inherited from

[`FetchAuthOptions`](#fetchauthoptions).[`clientAddress`](#clientaddress)

##### public?

```ts
readonly optional public?: readonly string[];
```

The paths that need no session. An entry matches exactly (`"/"` is the root only), or ends in `/*` to match one or
more segments below it (`"/blog/*"`). Matching is case-sensitive. Everything else needs the default requirement.

## Type Aliases

### ClientAddress

```ts
type ClientAddress<Args> = (req, ...args) => string | undefined;
```

Reads the client's address from what the runtime hands its fetch handler, never from a header (ADR 0009): Deno's
`info.remoteAddr.hostname`, Bun's `server.requestIP(req)?.address`. `Args` are the arguments after the request.

#### Type Parameters

| Type Parameter |
| ------ |
| `Args` *extends* `unknown`[] |

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `req` | `Request` |
| ...`args` | `Args` |

#### Returns

`string` \| `undefined`

***

### FetchAuthInfo

```ts
type FetchAuthInfo = 
  | {
  subject: string;
}
  | null;
```

What the handler receives with each request: the subject on a protected route, `null` on a public one.

#### Union Members

##### Type Literal

```ts
{
  subject: string;
}
```

###### subject

```ts
readonly subject: string;
```

The account the request's session belongs to.

***

`null`

***

### FetchHandler

```ts
type FetchHandler<Args> = (req, auth, ...args) => Response | Promise<Response>;
```

The app's handler. `Args` are the runtime's own arguments after the request (Deno's `info`, Bun's `server`), passed
on unchanged after the auth info.

#### Type Parameters

| Type Parameter |
| ------ |
| `Args` *extends* `unknown`[] |

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `req` | `Request` |
| `auth` | [`FetchAuthInfo`](#fetchauthinfo) |
| ...`args` | `Args` |

#### Returns

`Response` \| `Promise`\<`Response`\>

## Functions

### fetchAuth()

```ts
function fetchAuth<Args>(auth, options?): (req, ...args) => Promise<Response | null>;
```

Serves test-cap's `/auth/*` routes from a `Request`, and answers `null` for any other path, leaving its body unread,
so the app routes it itself. It protects nothing else: `withAuth` adds deny by default. A missing `clientAddress`
where production needs one throws a `ConfigError` here.

#### Type Parameters

| Type Parameter | Default type |
| ------ | ------ |
| `Args` *extends* `unknown`[] | \[\] |

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `auth` | [`Auth`](../index.md#auth)\<`string`\> |
| `options` | [`FetchAuthOptions`](#fetchauthoptions)\<`Args`\> |

#### Returns

(`req`, ...`args`) => `Promise`\<`Response` \| `null`\>

***

### withAuth()

```ts
function withAuth<Args>(
   auth, 
   handler, 
   options?
): (req, ...args) => Promise<Response>;
```

Wraps the app's fetch handler with test-cap: serves `/auth/*` and protects every other route at the default
requirement unless `options.public` lists it. A malformed public list, or a missing `clientAddress` where production
needs one, throws a `ConfigError` here. An error the app's handler throws reaches the runtime untouched; any other
failure is a fixed 500.

```ts
Deno.serve(withAuth(auth, handler, { public: ["/"], clientAddress: (req, info) => info.remoteAddr.hostname }))
```

#### Type Parameters

| Type Parameter | Default type |
| ------ | ------ |
| `Args` *extends* `unknown`[] | \[\] |

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `auth` | [`Auth`](../index.md#auth)\<`string`\> |
| `handler` | `NoInfer`\<[`FetchHandler`](#fetchhandler)\<`Args`\>\> |
| `options` | [`WithAuthOptions`](#withauthoptions)\<`Args`\> |

#### Returns

(`req`, ...`args`) => `Promise`\<`Response`\>
