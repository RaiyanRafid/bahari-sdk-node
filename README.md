# Bahari JavaScript / TypeScript SDKs

npm workspaces monorepo for signing in with Bahari Accounts from JavaScript.

| Package | Folder | Runs in | Purpose |
| --- | --- | --- | --- |
| `@bahari/node` | `packages/node` | Node.js 18+ | Core client (discovery, OIDC + PKCE, admin SSO, token verification, refresh, logout, back-channel logout, navigation, wallet, platform APIs) and the framework-agnostic auth layer (Express/Connect handlers, `requireBahari`, `SessionStore`) |
| `@bahari/nextjs` | `packages/nextjs` | Next.js App Router | Catch-all route handlers, `getBahariSession` for server components, edge-safe `bahariMiddleware` |
| `@bahari/react` | `packages/react` | Browser | `BahariProvider`, `useBahariSession`, `useBahariNavigation`, `SignInButton`, `SignOutButton` (no secrets, no tokens) |

The protocol mirrors the PHP core in `../php` and the Laravel package in `../laravel`.

## Develop

```bash
npm install
npm run build    # tsc for every package (node first)
npm test         # node:test for every package
```

Releases: bump `version` in the package's `package.json` and its `src/version.ts`, then `npm publish --access public`
from the package folder. Raise the supported/latest versions in Bahari admin → Connected apps → SDK versions.

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
