# @bahari/react

React components and hooks for Bahari Accounts sign-in. Browser-only and secret-free: it talks to your own backend
(the routes from [`@bahari/node`](../node) or [`@bahari/nextjs`](../nextjs)), never to Bahari directly, and never
sees a client secret or a token.

## Install

```bash
npm install @bahari/react
```

Your server needs `@bahari/node` or `@bahari/nextjs` with these environment variables (never expose them to the
browser): `BAHARI_ACCOUNTS_ISSUER`, `BAHARI_CLIENT_ID`, `BAHARI_CLIENT_SECRET`, `BAHARI_PLATFORM_KEY`. The redirect URLs
registered in Bahari are your server's `/auth/client/callback`, `/auth/admin/callback` and back-channel
`/auth/backchannel-logout`.

## Use

```tsx
import { BahariProvider, SignInButton, SignOutButton, useBahariNavigation, useBahariSession } from '@bahari/react';

export function App() {
  return (
    <BahariProvider prefix="/auth">
      <Header />
    </BahariProvider>
  );
}

function Header() {
  const { session, status } = useBahariSession();          // GET /auth/session
  if (status === 'loading') return null;
  if (!session) return <SignInButton />;                    // /auth/login (automatic admin detection)

  return (
    <>
      <span>{session.profile.name}</span>
      {session.profile.admin_access && <SignInButton kind="admin" returnTo="/admin">Admin</SignInButton>}
      <SignOutButton kind={session.kind} />                 {/* POST /auth/{kind}/logout */}
    </>
  );
}

function Switcher() {
  const { navigation, updatePinned } = useBahariNavigation();   // GET/PUT /auth/navigation
  // ...
}
```

- `BahariProvider` props: `prefix` (default `/auth`), `kind`, `initialSession` (from the server, skips the first
  request; `null` = signed out), `refetchOnFocus` (default `true`), `fetch`.
- `useBahariSession()` returns `{ session, status, error, refresh }`; `status` is `loading`, `authenticated`,
  `unauthenticated` or `error`.
- `useBahariNavigation({ kind? })` returns `{ navigation, status, error, reload, updatePinned(keys) }`.
- `<SignInButton kind? returnTo?>` renders a link; without `kind` it uses the automatic sign-in.
- `<SignOutButton kind>` renders a POST form (sign-out is never a GET link).
- Plain functions (also at `@bahari/react/core`): `loginHref`, `logoutAction`, `fetchSession`, `fetchNavigation`,
  `savePinned`.

The module is marked `'use client'` for the Next.js App Router. In Next.js, load the session on the server
(`bahari.getSession({ cookies })`) and pass it as `initialSession`.

## Automatic admin detection

`<SignInButton />` without `kind` starts the automatic sign-in: customers whose Bahari account is linked to an
administrator of this platform continue to the admin sign-in (password and 2FA on Bahari's admin host) and land in
the admin area. `session.profile.admin_access` tells you when someone has admin access.

## Updates

`npm install @bahari/react@latest`. The server packages report their version to Bahari and log a warning when it is
outdated.

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
