import {
  type BahariAuthOptions,
  type BahariCache,
  BahariAuth,
  BahariClient,
  type BahariClientOptions,
  type BahariConfigInput,
  Config,
  type Kind,
  MemoryCache,
  MemoryStore,
  type SessionStore,
  publicProfile,
} from '@bahari/node';
import { PACKAGE, VERSION } from './version.js';

export { PACKAGE, VERSION };
export { createBahariMiddleware, bahariMiddleware } from './middleware.js';
export type { BahariMiddlewareOptions } from './middleware.js';
export { AccessDeniedError, BahariAuth, BahariClient, BahariError, Config, HttpError, InvalidTokenError, MemoryCache, MemoryStore } from '@bahari/node';
export type { BahariAuthOptions, BahariProfile, Kind, SessionStore, StoredSession } from '@bahari/node';

export interface BahariNextOptions extends Partial<Omit<BahariAuthOptions, 'client'>> {
  /** A ready client. Default: one built from config (or the BAHARI_* environment variables). */
  client?: BahariClient;
  /** Default: Config.fromEnv() (BAHARI_ACCOUNTS_ISSUER, BAHARI_CLIENT_ID, BAHARI_CLIENT_SECRET, BAHARI_PLATFORM_KEY). */
  config?: Config | BahariConfigInput;
  clientOptions?: BahariClientOptions;
}

/** A Next.js App Router route handler. */
export type RouteHandler = (request: Request, context?: unknown) => Promise<Response>;

export interface BahariRouteHandlers {
  GET: RouteHandler;
  POST: RouteHandler;
  PUT: RouteHandler;
}

/** Anything with get(name) -> { value } (the Next.js cookies() store, or a test double). */
export interface CookieStoreLike {
  get(name: string): { value: string } | undefined;
}

/** The cookies() function from next/headers, its (awaited) result, or your own getter. */
export type CookieSource = CookieStoreLike | Promise<CookieStoreLike> | (() => CookieStoreLike | Promise<CookieStoreLike>);

export interface GetSessionOptions {
  cookies: CookieSource;
  /** "client" or "admin". Default: the customer session, then the admin session. */
  kind?: Kind;
}

/** What server components get: the rechecked profile. Tokens stay on the server. */
export interface BahariServerSession {
  kind: Kind;
  subject: string;
  profile: Record<string, unknown>;
}

export interface BahariNext {
  auth: BahariAuth;
  client: BahariClient;
  /** export const { GET, POST, PUT } = bahari.handlers  (in app/auth/[...bahari]/route.ts) */
  handlers: BahariRouteHandlers;
  /** The checked session for a server component, or null. */
  getSession(options: GetSessionOptions): Promise<BahariServerSession | null>;
  /** Like getSession, but calls redirect(loginPath) when signed out (pass redirect from next/navigation). */
  requireSession(options: GetSessionOptions & { redirect: (url: string) => never; returnTo?: string }): Promise<BahariServerSession>;
}

interface SharedStores {
  cache: BahariCache;
  sessions: SessionStore;
  state: BahariCache;
}

const SHARED = Symbol.for('@bahari/nextjs.stores');

/**
 * Next.js may load route handlers and server components as separate module instances; the in-memory defaults are
 * kept on globalThis so they share one store per process. Use shared stores (database / Redis) in production.
 */
function sharedStores(): SharedStores {
  const holder = globalThis as typeof globalThis & { [SHARED]?: SharedStores };
  holder[SHARED] ??= { cache: new MemoryCache(), sessions: new MemoryStore(), state: new MemoryCache() };

  return holder[SHARED];
}

/**
 * Creates the Bahari integration for a Next.js app. Create it once (for example in lib/bahari.ts) and import it from
 * the route handler and from server components.
 */
export function createBahari(options: BahariNextOptions = {}): BahariNext {
  const { client: givenClient, config, clientOptions, ...authOptions } = options;
  const shared = sharedStores();
  const client =
    givenClient ??
    new BahariClient(config ?? Config.fromEnv(), {
      cache: shared.cache,
      sdk: `${PACKAGE}/${VERSION}`,
      ...clientOptions,
    });
  const auth = new BahariAuth({
    sessionStore: shared.sessions,
    stateStore: shared.state,
    baseUrl: process.env.BAHARI_APP_URL || null,
    ...authOptions,
    client,
  });

  return {
    auth,
    client,
    handlers: createBahariRouteHandlers(auth),
    getSession: (getOptions) => getBahariSession(auth, getOptions),
    requireSession: (requireOptions) => requireBahariSession(auth, requireOptions),
  };
}

/**
 * Route handlers for app/auth/[...bahari]/route.ts:
 *
 *   export const { GET, POST, PUT } = createBahariRouteHandlers(bahari);
 *
 * Accepts the object from createBahari(), a BahariAuth, or options for createBahari().
 */
export function createBahariRouteHandlers(input: BahariNext | BahariAuth | BahariNextOptions = {}): BahariRouteHandlers {
  const auth = input instanceof BahariAuth ? input : 'auth' in input && input.auth instanceof BahariAuth ? input.auth : createBahari(input as BahariNextOptions).auth;
  const handler: RouteHandler = (request) => auth.fetch(request);

  return { GET: handler, POST: handler, PUT: handler };
}

/**
 * The checked Bahari session for a server component or server action. Every call rechecks the session with Bahari;
 * a session Bahari ended returns null (and is ended locally).
 *
 *   import { cookies } from 'next/headers';
 *   const session = await getBahariSession(bahari, { cookies });
 */
export async function getBahariSession(bahari: BahariNext | BahariAuth, options: GetSessionOptions): Promise<BahariServerSession | null> {
  const auth = bahari instanceof BahariAuth ? bahari : bahari.auth;
  const source = options.cookies;
  const store = await (typeof source === 'function' ? source() : source);
  const sid = store?.get(auth.cookieName)?.value ?? null;
  if (!sid) {
    return null;
  }
  const checked = await auth.sessionFromCookie(sid, options.kind);

  return checked ? { kind: checked.kind, subject: checked.subject, profile: publicProfile(checked.profile) } : null;
}

/** getBahariSession, or redirect(loginPath) when signed out. */
export async function requireBahariSession(
  bahari: BahariNext | BahariAuth,
  options: GetSessionOptions & { redirect: (url: string) => never; returnTo?: string },
): Promise<BahariServerSession> {
  const auth = bahari instanceof BahariAuth ? bahari : bahari.auth;
  const session = await getBahariSession(auth, options);
  if (!session) {
    const kind = options.kind ?? 'client';

    return options.redirect(auth.loginPath(kind, auth.safeReturnPath(kind, options.returnTo ?? null)));
  }

  return session;
}
