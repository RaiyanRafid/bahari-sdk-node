# @bahari/node

Sign in with Bahari Accounts from Node.js: customers (OIDC authorization code + PKCE) and platform admins (Bahari
admin SSO), a session recheck on every request, back-channel logout, the platform switcher, wallet links and platform
APIs. No runtime dependencies (global `fetch` and `node:crypto`). ESM and CommonJS.

You configure the issuer and your client credentials. Everything else, including the admin host and all API URLs, is
read from `https://accounts.baharione.com/.well-known/bahari-configuration` (cached; the last good copy is used for up
to a week if Bahari cannot be reached). When Bahari moves a domain, your app follows it without code or env changes.

Next.js apps: use [`@bahari/nextjs`](../nextjs). Browser UI: [`@bahari/react`](../react).

## Install

```bash
npm install @bahari/node
```

```dotenv
BAHARI_ACCOUNTS_ISSUER=https://accounts.baharione.com
BAHARI_CLIENT_ID=...
BAHARI_CLIENT_SECRET=...
BAHARI_PLATFORM_KEY=your-platform
# optional: the public origin of your app (used for redirect URLs)
BAHARI_APP_URL=https://your-app.example.com
```

Register these URLs for the app in Bahari (Connected apps does this for you):

| Purpose | URL |
| --- | --- |
| Customer callback | `https://your-app/auth/client/callback` |
| Admin callback | `https://your-app/auth/admin/callback` |
| Back-channel logout | `https://your-app/auth/backchannel-logout` |

## Express / Connect

```js
import express from 'express';
import { BahariClient, Config, createBahariAuth } from '@bahari/node';

const client = new BahariClient(Config.fromEnv());
const auth = createBahariAuth({
  client,
  baseUrl: process.env.BAHARI_APP_URL,
  prefix: '/auth',
  kinds: { client: { path: '/dashboard' }, admin: { path: '/admin' } },
  // sessionStore: your database store,  stateStore: your Redis cache (see "Production")
});

const app = express();
app.use(auth.handler);                                   // all /auth/* routes
app.use('/dashboard', auth.requireBahari('client'));     // customers
app.use('/admin', auth.requireBahari('admin'));          // platform admins

app.get('/dashboard', async (req, res) => {
  res.json({ hello: req.bahari.profile.name });          // req.bahari = { kind, subject, profile, session }
});
```

Routes (under `prefix`, default `/auth`):

| Route | |
| --- | --- |
| `GET /auth/login` | Automatic sign-in: customer first, linked admins continue to the admin sign-in |
| `GET /auth/{client,admin}/login?return_to=/dashboard/...` | Sign in as that kind |
| `GET /auth/{client,admin}/callback` | Redirect URLs registered in Bahari |
| `POST /auth/{client,admin}/logout` | Ends the local and the Bahari session (use a form, not a link) |
| `POST /auth/backchannel-logout` | Bahari's signed logout notifications (de-duplicated per `jti`) |
| `GET /auth/session[?kind=]` | `{ kind, profile }` of the rechecked session, never tokens; `401` when signed out |
| `GET /auth/navigation[?kind=]` | The platform switcher (`{ data }`) |
| `PUT /auth/navigation` | `{ "pinned_keys": [...] }` for customers; Bahari's `422` is passed through |

`requireBahari(kind?)` rechecks the session with Bahari on every request (rotating client tokens when they expire
within 30 seconds). Suspended accounts, removed admin roles and revoked sessions end at once; any failure (including
Bahari being unreachable) ends the local session and redirects to the sign-in (API callers asking for JSON get `401`).
Without `kind`, the kind comes from the path (`kinds.*.path`), else `client`.

The browser only holds an opaque, random session id in an `HttpOnly; Secure; SameSite=Lax` cookie (`bahari_sid`).
Pending sign-ins (state, nonce, PKCE verifier) and Bahari sessions with their tokens stay on the server. Return paths
are restricted to the kind's area (no external URLs, `//`, backslashes, control characters or `..`).

Other frameworks: `auth.handle(request)` takes a Web `Request` (or `fromNodeRequest(req)`) and returns a neutral
result (`toWebResponse()` / `writeNodeResponse()`); `auth.fetch(request)` returns a Web `Response`;
`auth.authenticate(request, kind?)` is the framework-free form of `requireBahari`.

## Automatic admin detection

Send everyone to `GET /auth/login`. After the customer signs in, if their Bahari account is linked to an administrator
who may manage this app's platform (`profile.admin_access` is set), the browser continues to the admin sign-in, where
Bahari asks for the admin's password and 2FA on its admin host. The admin session is only created when the admin's
`user_id` is the customer who started the sign-in; otherwise the person stays in the customer area. Disable with
`autoAdmin: false`.

## The client on its own

```js
import { BahariClient } from '@bahari/node';

const bahari = new BahariClient({ issuer: 'https://accounts.baharione.com', clientId, clientSecret, platform: 'reseller' });

// 1. Start: keep login.transaction in the server-side session under login.state; redirect to login.url
const login = await bahari.beginLogin('client', 'https://your-app/auth/client/callback');
// 2. Callback: look the transaction up by state, then
const identity = await bahari.completeLogin(transaction, code);  // { subject, profile, tokens (store encrypted), accessExpiresIn }
// 3. Later requests: AccessDeniedError means "sign the person out"; store tokens when tokensChanged
const fresh = await bahari.refresh('client', tokens, subject, secondsUntilAccessExpiry);
// Logout and back-channel logout
await bahari.revoke('client', tokens);
const location = await bahari.logoutUrl('client', 'https://your-app/');
const claims = await bahari.verifyLogoutToken(logoutToken);       // end sessions of claims.sub once per claims.jti

await bahari.url('client.profile_url');                           // any URL from discovery
await bahari.walletUrl('/dashboard');
await bahari.navigation('client', tokens, '/dashboard');
await bahari.updatePinned(tokens, ['reseller', 'sms']);
await bahari.api('GET', 'platform-wallet-balances');              // machine token (client credentials)
bahari.sdkStatus();                                               // ok | outdated | unsupported | unknown
```

Errors: `BahariError` (base), `HttpError` (`.status`, `.response`), `InvalidTokenError`, `AccessDeniedError`.

Options: `new BahariClient(config, { fetch, cache, seal, unseal, logger, timeout })`. Requests never follow
redirects and time out after 10 seconds. ID and logout tokens must be RS256 with a `kid`; the JWKS is cached for 5
minutes and fetched again once when a key is unknown.

## Roles, maintenance and branding (0.4.0)

```ts
bahari.role(identity);          // 'SUPER_ADMIN' | 'ADMIN' | 'USER'
bahari.isAdmin(identity);       // true only for an admin session of this app
await bahari.maintenance();     // { enabled, message } — show a banner
await bahari.branding();        // logos, favicon, brand colour, access mode and support contact
BahariClient.linkedUserId(identity);
```

Back-channel logout now also ends admin sessions whose profile `user_id` is the account Bahari names. A custom
`SessionStore` can implement the optional `revokeLinkedUser(userId)`; without it, admin sessions end at their next
check with Bahari.

## Production

The defaults (`MemoryStore`, `MemoryCache`) keep everything in one process. With several processes or servers:

- `sessionStore`: implement `SessionStore` (`create`, `find`, `update`, `revoke`, `revokeSubject`) on your database and
  encrypt `tokens` at rest.
- `stateStore` and the client's `cache`: a shared `BahariCache` (`get`, `set(key, value, ttlSeconds)`, `delete`), for
  example Redis. Pass `seal`/`unseal` to encrypt cached machine tokens.
- Set `baseUrl` so redirect URLs never depend on the `Host` header. For plain-http local development in Safari, set
  `cookieSecure: false`.

## Updates

Every request sends `X-Bahari-SDK: @bahari/node/<version>`. Bahari shows the version per app and answers with
`X-Bahari-SDK-Status`; when it is `outdated` or `unsupported` the package logs one warning per process
(`client.sdkStatus()` returns the last value). Update with `npm install @bahari/node@latest`.

## License

MIT


## No local authentication

The app has no sign-in of its own. Bahari Accounts does sign-in, registration, passwords, password reset,
verification, 2FA and administrator sign-in. Remove any login or registration forms, password fields and local admin
logins, and store no passwords: local users keep only the Bahari ID and copies of name and email.

| Button | Route |
| --- | --- |
| Sign in | `GET /auth/login` |
| Create account | `GET /auth/register` |
| Administrator sign-in (optional) | `GET /auth/admin/login` |
| Sign out | `POST /auth/{client\|admin}/logout` |

Clicking Sign in opens Bahari ("Sign in to continue to *your app*"). After sign-in or registration Bahari sends the
person straight back to the page they wanted in your app; connected apps see no consent screen. Sign out ends the app
session and Bahari's, then returns to your home page without a confirmation page (the package sends the ID token as
`id_token_hint`).
