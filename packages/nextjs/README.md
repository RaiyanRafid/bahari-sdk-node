# @bahari/nextjs

Sign in with Bahari Accounts in a Next.js App Router app: one catch-all route handler, sessions in server components
and a middleware gate. Built on [`@bahari/node`](../node); tokens never reach the browser.

## Install

```bash
npm install @bahari/nextjs
```

```dotenv
BAHARI_ACCOUNTS_ISSUER=https://accounts.baharione.com
BAHARI_CLIENT_ID=...
BAHARI_CLIENT_SECRET=...
BAHARI_PLATFORM_KEY=your-platform
BAHARI_APP_URL=https://your-app.example.com
```

Register these URLs for the app in Bahari (Connected apps does this for you):

| Purpose | URL |
| --- | --- |
| Customer callback | `https://your-app/auth/client/callback` |
| Admin callback | `https://your-app/auth/admin/callback` |
| Back-channel logout | `https://your-app/auth/backchannel-logout` |

## Set up

```ts
// lib/bahari.ts
import { createBahari } from '@bahari/nextjs';

export const bahari = createBahari({
  kinds: { client: { path: '/dashboard' }, admin: { path: '/admin' } },
  // sessionStore / stateStore: shared stores in production (see @bahari/node)
});
```

```ts
// app/auth/[...bahari]/route.ts
import { bahari } from '@/lib/bahari';

export const { GET, POST, PUT } = bahari.handlers;   // or createBahariRouteHandlers(bahari)
export const dynamic = 'force-dynamic';
```

This serves `/auth/login`, `/auth/{client,admin}/login|callback|logout`, `/auth/backchannel-logout`, `/auth/session`
and `/auth/navigation` (see [`@bahari/node`](../node#express--connect)).

## Server components

```tsx
// app/dashboard/page.tsx
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { bahari } from '@/lib/bahari';

export default async function Dashboard() {
  const session = await bahari.requireSession({ cookies, redirect, kind: 'client', returnTo: '/dashboard' });
  // or: const session = await bahari.getSession({ cookies });   // null when signed out

  return <h1>Hello {String(session.profile.name)}</h1>;
}
```

Each call rechecks the session with Bahari and fails closed. The result is `{ kind, subject, profile }` without tokens,
so it is safe to pass to client components. `getBahariSession(bahari, { cookies })` is the same as a function.

## Middleware

```ts
// middleware.ts (or proxy.ts in Next 16)
import { NextResponse } from 'next/server';
import { bahariMiddleware } from '@bahari/nextjs/middleware';

export function middleware(request: Request) {
  return bahariMiddleware(request) ?? NextResponse.next();
}
export const config = { matcher: ['/dashboard/:path*', '/admin/:path*'] };
```

The middleware entry is edge-safe. It only checks that a session cookie exists and sends everyone else to the
sign-in of the area's kind; the real check with Bahari happens in `getSession`/`requireSession` and the route
handlers. Customise with `createBahariMiddleware({ prefix, kinds, cookieName })`.

## Automatic admin detection

Link "Sign in" to `/auth/login`. Customers whose Bahari account is linked to an administrator of this platform
continue to the admin sign-in (Bahari asks for the admin password and 2FA on its admin host) and land in `/admin`.
The admin session is only created when the admin's `user_id` matches the customer who started the sign-in. Turn it off
with `createBahari({ autoAdmin: false })`.

## Notes

- The in-memory defaults are kept on `globalThis` so route handlers and server components share them in one process.
  Use a database `SessionStore` and a shared cache (Redis) when you run more than one instance.
- `next` is an optional peer dependency; the package only uses Web `Request`/`Response`.

## Updates

Requests send `X-Bahari-SDK: @bahari/nextjs/<version>`; outdated or unsupported versions are logged once per process.
Update with `npm install @bahari/nextjs@latest @bahari/node@latest`.

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
