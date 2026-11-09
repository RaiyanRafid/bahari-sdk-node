import { randomBytes } from 'node:crypto';
import type { ServerResponse } from 'node:http';
import { type BahariCache, MemoryCache } from '../cache.js';
import type { BahariClient, NavigationResult } from '../client.js';
import { AccessDeniedError } from '../errors.js';
import { kindForPath, normalizeAreaPath, safeReturnPath } from '../return-path.js';
import type { BahariProfile, Kind, Logger, LoginTransaction } from '../types.js';
import { KeyedLock, isObject, sha256Hex } from '../util.js';
import { parseCookies, serializeCookie } from './cookies.js';
import {
  type AuthRequest,
  type AuthResult,
  type NodeRequest,
  PayloadTooLargeError,
  expectsJson,
  fromNodeRequest,
  fromWebRequest,
  isAuthRequest,
  json,
  redirect,
  text,
  toWebResponse,
  writeNodeResponse,
} from './http.js';
import { MemoryStore, type SessionStore, type StoredSession } from './session-store.js';

export interface KindSettings {
  /** The area this kind signs in to and the default return path, for example "/dashboard" or "/admin". */
  path: string;
}

export interface BahariAuthOptions {
  client: BahariClient;
  /** Bahari sessions (server-side, with tokens). Default: MemoryStore (one process only). */
  sessionStore?: SessionStore;
  /** Server-side browser sessions (pending sign-ins) and logout de-duplication. Default: MemoryCache. */
  stateStore?: BahariCache;
  /** Route prefix. Default "/auth". */
  prefix?: string;
  /** Which kinds are enabled and their areas. Default { client: { path: '/dashboard' }, admin: { path: '/admin' } }. */
  kinds?: Partial<Record<Kind, KindSettings>>;
  /** Public origin of this app, for example https://app.example.com. Default: taken from each request. */
  baseUrl?: string | null;
  /** Cookie that holds the opaque browser session id. Default "bahari_sid". */
  cookieName?: string;
  /** Default true unless baseUrl is plain http. */
  cookieSecure?: boolean;
  cookieDomain?: string;
  /** Seconds a sign-in lasts locally. Default 8 hours. */
  sessionTtl?: number;
  /** After an automatic sign-in, continue to the admin sign-in when the account is linked to an admin. Default true. */
  autoAdmin?: boolean;
  /** Where Bahari sends the browser after a customer logout. Default `${baseUrl}/`. */
  postLogoutRedirect?: string | null;
  logger?: Logger;
}

/** A checked session, attached to Express requests as req.bahari. */
export interface BahariRequestSession {
  kind: Kind;
  subject: string;
  /** The rechecked Bahari profile (server-side; safe to render, contains no tokens). */
  profile: BahariProfile;
  /** The stored session including tokens. Never send it to the browser. */
  session: StoredSession;
}

export type AuthOutcome = ({ ok: true } & BahariRequestSession) | { ok: false; kind: Kind; response: AuthResult };

export interface PublicSession {
  kind: Kind;
  profile: Record<string, unknown>;
}

interface PendingTransaction extends LoginTransaction {
  returnTo: string;
  auto?: boolean;
  expectedUserId?: string;
}

interface WebState {
  sessions: Partial<Record<Kind, string>>;
  transactions: Record<string, PendingTransaction>;
  expectedAdminUserId?: string;
}

type Next = (error?: unknown) => void;

const SID = /^[A-Za-z0-9_-]{43}$/;
const STATE = /^[a-f0-9]{64}$/;
const MAX_PENDING = 10;
const SECRET_KEY = /(?:^|_)(?:tokens?|secret)$/i;

/**
 * Removes every token- or secret-like key (deeply) so a profile can be sent to the browser.
 */
export function publicProfile(profile: unknown): Record<string, unknown> {
  const strip = (value: unknown): unknown => {
    if (Array.isArray(value)) {
      return value.map(strip);
    }
    if (isObject(value)) {
      const result: Record<string, unknown> = {};
      for (const [key, item] of Object.entries(value)) {
        if (!SECRET_KEY.test(key)) {
          result[key] = strip(item);
        }
      }

      return result;
    }

    return value;
  };
  const result = strip(profile);

  return isObject(result) ? result : {};
}

/**
 * Server-side browser session: the cookie only carries a random id. Holds pending sign-ins, the signed-in Bahari
 * session id per kind and the expected admin user of an automatic sign-in.
 */
class WebSession {
  readonly cookies: string[] = [];

  private previous: string | null = null;

  constructor(
    private readonly auth: BahariAuth,
    public sid: string | null,
    public state: WebState,
  ) {}

  /** A new id on the next save (session fixation protection). */
  regenerate(): void {
    if (this.sid) {
      this.previous = this.sid;
    }
    this.sid = null;
  }

  async save(): Promise<void> {
    const store = this.auth.stateStore;
    if (!this.sid) {
      this.sid = randomBytes(32).toString('base64url');
      this.cookies.push(this.auth.sessionCookie(this.sid));
    }
    if (this.previous) {
      await store.delete(webKey(this.previous));
      this.previous = null;
    }
    await store.set(webKey(this.sid), this.state, this.auth.sessionTtl);
  }
}

function webKey(sid: string): string {
  return `bahari:web:${sha256Hex(sid)}`;
}

/**
 * Framework-agnostic Bahari sign-in for your server. Routes (under prefix, default /auth):
 *
 * - GET  /login                  automatic sign-in (customer first; admins continue to the admin sign-in)
 * - GET  /register               "Create account": Bahari registration, then the same automatic sign-in
 * - GET  /:kind/login            kind = client | admin, optional ?return_to=/dashboard/...
 * - GET  /:kind/callback         redirect URL registered in Bahari
 * - POST /:kind/logout
 * - POST /backchannel-logout     Bahari's signed logout notifications
 * - GET  /session[?kind=]        { kind, profile } of the rechecked session, never tokens; 401 when signed out
 * - GET  /navigation[?kind=]     the platform switcher
 * - PUT  /navigation             { pinned_keys: [...] } (customers)
 *
 * Use handle()/fetch() with Web Requests, handler with Express/Connect, and requireBahari() to protect routes.
 */
export class BahariAuth {
  readonly client: BahariClient;

  readonly sessions: SessionStore;

  readonly stateStore: BahariCache;

  readonly prefix: string;

  readonly kinds: Partial<Record<Kind, KindSettings>>;

  readonly baseUrl: string | null;

  readonly cookieName: string;

  readonly sessionTtl: number;

  readonly autoAdmin: boolean;

  private readonly cookieSecure: boolean;

  private readonly cookieDomain: string | undefined;

  private readonly postLogoutRedirect: string | null;

  private readonly logger: Logger;

  private readonly locks = new KeyedLock();

  constructor(options: BahariAuthOptions) {
    this.client = options.client;
    this.sessions = options.sessionStore ?? new MemoryStore(() => this.client.now());
    this.stateStore = options.stateStore ?? new MemoryCache(() => this.client.now() * 1000);
    this.prefix = normalizeAreaPath(options.prefix ?? '/auth');
    if (this.prefix === '/') {
      throw new TypeError('The Bahari route prefix must not be "/".');
    }
    this.kinds = options.kinds ?? { client: { path: '/dashboard' }, admin: { path: '/admin' } };
    this.baseUrl = options.baseUrl ? new URL(options.baseUrl).origin : null;
    this.cookieName = options.cookieName ?? 'bahari_sid';
    this.cookieSecure = options.cookieSecure ?? !(this.baseUrl ?? '').startsWith('http://');
    this.cookieDomain = options.cookieDomain;
    this.sessionTtl = options.sessionTtl ?? 8 * 3600;
    this.autoAdmin = options.autoAdmin ?? true;
    this.postLogoutRedirect = options.postLogoutRedirect ?? null;
    this.logger = options.logger ?? console;
  }

  // ---------------------------------------------------------------- routing

  /** Handles a request under the prefix; null when the path is not a Bahari route. */
  async handle(input: AuthRequest | Request): Promise<AuthResult | null> {
    const request = isAuthRequest(input) ? input : fromWebRequest(input);
    const path = request.url.pathname.replace(/\/+$/, '');
    if (!path.startsWith(`${this.prefix}/`)) {
      return null;
    }
    const segments = path.slice(this.prefix.length + 1).split('/');
    const method = request.method === 'HEAD' ? 'GET' : request.method;
    try {
      if (segments.length === 1) {
        switch (segments[0]) {
          case 'login':
            return method === 'GET' ? await this.login(request, 'client', true) : notAllowed('GET');
          case 'register':
            return method === 'GET' ? await this.login(request, 'client', true, 'create') : notAllowed('GET');
          case 'session':
            return method === 'GET' ? await this.sessionJson(request) : notAllowed('GET');
          case 'navigation':
            return method === 'GET' ? await this.getNavigation(request) : method === 'PUT' ? await this.putNavigation(request) : notAllowed('GET, PUT');
          case 'backchannel-logout':
            return method === 'POST' ? await this.backchannelLogout(request) : notAllowed('POST');
          default:
            return null;
        }
      }
      if (segments.length === 2 && this.enabled(segments[0])) {
        const kind = segments[0];
        switch (segments[1]) {
          case 'login':
            return method === 'GET' ? await this.login(request, kind, false) : notAllowed('GET');
          case 'callback':
            return method === 'GET' ? await this.callback(request, kind) : notAllowed('GET');
          case 'logout':
            return method === 'POST' ? await this.logout(request, kind) : notAllowed('POST');
          default:
            return null;
        }
      }
    } catch (error) {
      this.logger.warn('Bahari request failed', { path, error: describe(error) });

      return text(500, 'Bahari sign-in failed. Please try again.');
    }

    return null;
  }

  /** Web-standard handler (Next.js route handlers, Hono, Bun, Deno, ...). Unknown paths answer 404. */
  async fetch(request: Request): Promise<Response> {
    const result = await this.handle(request);

    return toWebResponse(result ?? text(404, 'Not found.'));
  }

  /** Express/Connect middleware for all Bahari routes: app.use(auth.handler). */
  readonly handler = (req: NodeRequest, res: ServerResponse, next?: Next): void => {
    this.handle(fromNodeRequest(req, this.baseUrl)).then(
      (result) => {
        if (result) {
          writeNodeResponse(res, result);
        } else if (next) {
          next();
        } else {
          writeNodeResponse(res, text(404, 'Not found.'));
        }
      },
      (error) => (next ? next(error) : writeNodeResponse(res, text(500, 'Bahari sign-in failed.'))),
    );
  };

  /**
   * Express/Connect middleware that requires a live Bahari session. Every request is rechecked with Bahari (tokens
   * rotate when needed); any failure ends the local session (fail closed). Sets req.bahari and res.locals.bahari.
   * Without kind, the kind comes from the request path (kinds[*].path), else "client".
   */
  requireBahari(kind?: Kind): (req: NodeRequest & { bahari?: BahariRequestSession }, res: ServerResponse & { locals?: Record<string, unknown> }, next: Next) => void {
    if (kind !== undefined && !this.enabled(kind)) {
      throw new TypeError(`Bahari kind "${kind}" is not enabled.`);
    }

    return (req, res, next) => {
      this.authenticate(fromNodeRequest(req, this.baseUrl), kind).then((outcome) => {
        if (outcome.ok) {
          req.bahari = { kind: outcome.kind, subject: outcome.subject, profile: outcome.profile, session: outcome.session };
          if (res.locals) {
            res.locals.bahari = { kind: outcome.kind, profile: publicProfile(outcome.profile) };
          }
          next();
        } else {
          writeNodeResponse(res, outcome.response);
        }
      }, next);
    };
  }

  /**
   * Checks the request's session for kind (default: from the path). On failure returns the response to send: a
   * redirect to the sign-in, or 401 JSON for API callers.
   */
  async authenticate(input: AuthRequest | Request, kind?: Kind): Promise<AuthOutcome> {
    const request = isAuthRequest(input) ? input : fromWebRequest(input);
    const resolved = kind ?? this.kindFor(request.url.pathname);
    const web = await this.load(request);
    const session = await this.check(web, resolved);
    if (session) {
      return { ok: true, kind: resolved, subject: session.subject, profile: session.profile, session };
    }
    if (expectsJson(request)) {
      return { ok: false, kind: resolved, response: json(401, { message: 'Bahari sign-in is required.' }) };
    }

    return { ok: false, kind: resolved, response: redirect(this.loginPath(resolved, request.url.pathname + request.url.search)) };
  }

  /**
   * The checked session behind a session cookie value (for server components). Without kind, the customer session
   * is tried first, then the admin session. Null when signed out or when Bahari ended the session.
   */
  async sessionFromCookie(sid: string | null | undefined, kind?: Kind): Promise<BahariRequestSession | null> {
    const web = await this.loadSid(sid ?? null);
    for (const candidate of kind ? [kind] : this.enabledKinds()) {
      const session = await this.check(web, candidate);
      if (session) {
        return { kind: candidate, subject: session.subject, profile: session.profile, session };
      }
    }

    return null;
  }

  // ---------------------------------------------------------------- helpers

  /** The kind a path belongs to (kinds[*].path), else "client". */
  kindFor(pathname: string): Kind {
    return kindForPath(this.kinds, pathname, 'client');
  }

  areaPath(kind: Kind): string {
    return normalizeAreaPath(this.kinds[kind]?.path ?? '/');
  }

  /** A local return path inside the kind's area, or the area itself. Blocks external URLs and traversal. */
  safeReturnPath(kind: Kind, value: unknown): string {
    return safeReturnPath(this.areaPath(kind), value);
  }

  /** "/auth/login" (automatic), or "/auth/{kind}/login", with an optional return_to. */
  loginPath(kind?: Kind | null, returnTo?: string | null): string {
    const path = kind ? `${this.prefix}/${kind}/login` : `${this.prefix}/login`;

    return returnTo ? `${path}?return_to=${encodeURIComponent(returnTo)}` : path;
  }

  logoutPath(kind: Kind): string {
    return `${this.prefix}/${kind}/logout`;
  }

  /** The platform switcher for a checked session. */
  navigation(session: StoredSession): Promise<NavigationResult> {
    return this.client.navigation(session.kind, session.tokens, this.areaPath('client'));
  }

  /** The browser-safe view of a session. */
  publicSession(session: { kind: Kind; profile: unknown }): PublicSession {
    return { kind: session.kind, profile: publicProfile(session.profile) };
  }

  /** The Set-Cookie value for a browser session id. */
  sessionCookie(sid: string, maxAge: number = this.sessionTtl): string {
    return serializeCookie(this.cookieName, sid, { maxAge, secure: this.cookieSecure, httpOnly: true, sameSite: 'Lax', path: '/', domain: this.cookieDomain });
  }

  // ---------------------------------------------------------------- route handlers

  private async login(request: AuthRequest, kind: Kind, auto: boolean, prompt: 'create' | null = null): Promise<AuthResult> {
    if (!this.client.config.configured()) {
      return text(503, 'Bahari sign-in is being configured.');
    }
    const web = await this.load(request);
    const login = await this.client.beginLogin(kind, `${this.origin(request)}${this.prefix}/${kind}/callback`, { prompt });
    const transaction: PendingTransaction = { ...login.transaction, returnTo: this.safeReturnPath(kind, request.url.searchParams.get('return_to')) };
    if (auto) {
      transaction.auto = true;
    }
    if (kind === 'admin' && web.state.expectedAdminUserId) {
      transaction.expectedUserId = web.state.expectedAdminUserId;
      delete web.state.expectedAdminUserId;
    }
    this.prunePending(web.state);
    web.state.transactions[sha256Hex(login.state)] = transaction;
    await web.save();

    return redirect(login.url, 302, {}, web.cookies);
  }

  private async callback(request: AuthRequest, kind: Kind): Promise<AuthResult> {
    const query = request.url.searchParams;
    const state = query.get('state');
    const code = query.get('code');
    const error = query.get('error');
    if (!state || !STATE.test(state) || (code !== null && code.length > 20000) || (error !== null && error.length > 100)) {
      return text(422, 'Invalid sign-in response. Please start again.');
    }
    const web = await this.load(request);
    const key = sha256Hex(state);
    const transaction = web.state.transactions[key];
    if (transaction) {
      delete web.state.transactions[key];
      await web.save();
    }
    if (!transaction || transaction.kind !== kind || this.client.now() - Number(transaction.createdAt ?? 0) > 600) {
      return text(422, 'Sign-in expired. Please start again.');
    }
    if (error || !code) {
      return text(422, 'Sign-in was not approved.');
    }
    const headers = { 'Referrer-Policy': 'no-referrer' };
    let session: StoredSession;
    let identity;
    try {
      identity = await this.client.completeLogin(transaction, code);
      if (kind === 'admin' && transaction.expectedUserId !== undefined && identity.profile.user_id !== transaction.expectedUserId) {
        // Automatic sign-in: the admin who signed in is not linked to the customer who started it. No admin session.
        this.logger.warn('Bahari admin sign-in ignored: the administrator is not linked to the signed-in customer.', { kind });
        try {
          await this.client.revoke('admin', identity.tokens);
        } catch (revokeError) {
          this.logger.info?.('Bahari admin session revoke failed.', { error: describe(revokeError) });
        }

        return redirect(this.safeReturnPath('client', null), 302, headers, web.cookies);
      }
      const now = this.client.now();
      session = await this.sessions.create({
        kind,
        subject: identity.subject,
        tokens: identity.tokens,
        profile: identity.profile,
        accessExpiresAt: identity.accessExpiresIn !== null ? now + identity.accessExpiresIn : null,
        expiresAt: now + this.sessionTtl,
      });
    } catch (failure) {
      this.logger.warn('Bahari sign-in failed', { kind, error: describe(failure) });

      return text(503, 'Sign-in could not be completed. Please start again or contact support.', {}, web.cookies);
    }
    web.regenerate();
    web.state.sessions[kind] = session.id;
    let location = transaction.returnTo ?? this.safeReturnPath(kind, null);
    if (kind === 'client' && transaction.auto && this.autoAdmin && this.enabled('admin') && this.hasAdminAccess(identity.profile)) {
      web.state.expectedAdminUserId = identity.subject;
      location = this.loginPath('admin', this.safeReturnPath('admin', null));
    }
    await web.save();

    return redirect(location, 302, headers, web.cookies);
  }

  private async logout(request: AuthRequest, kind: Kind): Promise<AuthResult> {
    if (!this.sameOrigin(request)) {
      return text(403, 'Cross-site logout is not allowed.');
    }
    const web = await this.load(request);
    const id = web.state.sessions[kind];
    let idToken: string | null = null;
    if (web.sid && id) {
      delete web.state.sessions[kind];
      const stored = await this.sessions.find(id, kind);
      if (stored) {
        idToken = typeof stored.tokens.id_token === 'string' ? stored.tokens.id_token : null;
        await this.sessions.revoke(stored.id);
        try {
          await this.client.revoke(kind, stored.tokens);
        } catch (error) {
          this.logger.info?.('Bahari session revoke failed; the local session is ended.', { kind, error: describe(error) });
        }
      }
      web.regenerate();
      await web.save();
    }
    const location = await this.client.logoutUrl(kind, this.postLogoutRedirect ?? `${this.origin(request)}/`, idToken);

    return redirect(location, 303, { 'Cache-Control': 'no-store' }, web.cookies);
  }

  private async backchannelLogout(request: AuthRequest): Promise<AuthResult> {
    let body: string;
    try {
      body = await request.text(65536);
    } catch (error) {
      if (error instanceof PayloadTooLargeError) {
        return json(413, { message: 'Payload too large.' });
      }
      throw error;
    }
    let token: unknown = null;
    if ((request.header('content-type') ?? '').includes('json')) {
      try {
        const data = JSON.parse(body) as unknown;
        token = isObject(data) ? data.logout_token : null;
      } catch {
        token = null;
      }
    } else {
      token = new URLSearchParams(body).get('logout_token');
    }
    if (typeof token !== 'string' || token === '' || token.length > 20000) {
      return json(422, { message: 'The logout_token field is required.' });
    }
    let claims;
    try {
      claims = await this.client.verifyLogoutToken(token);
    } catch {
      return json(422, { message: 'Invalid logout notification.' });
    }
    const key = `bahari-logout-jti:${sha256Hex(String(claims.jti))}`;
    await this.locks.run(key, async () => {
      const seen = await this.stateStore.get(key);
      if (seen !== undefined && seen !== null) {
        return;
      }
      await this.sessions.revokeSubject('client', claims.sub);
      await this.stateStore.set(key, true, 300);
    });

    return json(200, { received: true });
  }

  private async sessionJson(request: AuthRequest): Promise<AuthResult> {
    const requested = request.url.searchParams.get('kind');
    if (requested !== null && !this.enabled(requested)) {
      return json(404, { message: 'Unknown kind.' });
    }
    const web = await this.load(request);
    for (const kind of requested ? [requested] : this.enabledKinds()) {
      const session = await this.check(web, kind);
      if (session) {
        return json(200, this.publicSession(session));
      }
    }

    return json(401, { message: 'Bahari sign-in is required.' });
  }

  private async getNavigation(request: AuthRequest): Promise<AuthResult> {
    const kind = request.url.searchParams.get('kind') ?? 'client';
    if (!this.enabled(kind)) {
      return json(404, { message: 'Unknown kind.' });
    }
    const session = await this.check(await this.load(request), kind);
    if (!session) {
      return json(401, { message: 'Bahari sign-in is required.' });
    }
    try {
      return json(200, { data: await this.navigation(session) });
    } catch (error) {
      this.logger.warn('Bahari navigation failed', { kind, error: describe(error) });

      return json(502, { message: 'The platform switcher is unavailable.' });
    }
  }

  private async putNavigation(request: AuthRequest): Promise<AuthResult> {
    if (!this.sameOrigin(request)) {
      return json(403, { message: 'Cross-site requests are not allowed.' });
    }
    if (!(request.header('content-type') ?? '').includes('application/json')) {
      return json(415, { message: 'Send application/json.' });
    }
    let data: unknown;
    try {
      data = JSON.parse(await request.text(16384));
    } catch (error) {
      return error instanceof PayloadTooLargeError ? json(413, { message: 'Payload too large.' }) : json(400, { message: 'Invalid JSON.' });
    }
    const keys = isObject(data) ? data.pinned_keys : null;
    if (!Array.isArray(keys) || keys.length > 100 || !keys.every((key) => typeof key === 'string' && key.length <= 100)) {
      return json(422, { message: 'pinned_keys must be a list of platform keys.', errors: { pinned_keys: ['pinned_keys must be a list of platform keys.'] } });
    }
    const session = await this.check(await this.load(request), 'client');
    if (!session) {
      return json(401, { message: 'Bahari sign-in is required.' });
    }
    try {
      const response = await this.client.updatePinned(session.tokens, keys as string[]);

      return { ...json(response.status, null), body: response.body || '{}' };
    } catch (error) {
      this.logger.warn('Bahari pinned platforms update failed', { error: describe(error) });

      return json(502, { message: 'The platform switcher is unavailable.' });
    }
  }

  // ---------------------------------------------------------------- sessions

  /** Rechecks the session of kind in this browser session; ends it (fail closed) on any problem. */
  private async check(web: WebSession, kind: Kind): Promise<StoredSession | null> {
    const id = web.state.sessions[kind];
    if (!id) {
      return null;
    }
    const stored = await this.sessions.find(id, kind);
    if (stored) {
      try {
        return await this.recheck(stored);
      } catch (error) {
        this.logger.info?.('Bahari session ended', { kind, error: describe(error) });
        await this.sessions.revoke(stored.id);
      }
    }
    delete web.state.sessions[kind];
    if (web.sid) {
      await web.save();
    }

    return null;
  }

  /**
   * Rechecks a stored session with Bahari (rotating client tokens when needed) and saves the result.
   *
   * @throws AccessDeniedError (or another error) when the session must end.
   */
  async recheck(stored: StoredSession): Promise<StoredSession> {
    return this.locks.run(`bahari-session:${stored.id}`, async () => {
      const fresh = await this.sessions.find(stored.id, stored.kind);
      if (!fresh) {
        throw new AccessDeniedError('The session has ended.');
      }
      const now = this.client.now();
      const identity = await this.client.refresh(fresh.kind, fresh.tokens, fresh.subject, fresh.accessExpiresAt !== null ? fresh.accessExpiresAt - now : null);
      const updated = await this.sessions.update(
        fresh.id,
        identity.tokensChanged
          ? { profile: identity.profile, tokens: identity.tokens, accessExpiresAt: now + (identity.accessExpiresIn ?? 900) }
          : { profile: identity.profile },
      );
      if (!updated) {
        throw new AccessDeniedError('The session has ended.');
      }

      return updated;
    });
  }

  private async load(request: AuthRequest): Promise<WebSession> {
    return this.loadSid(parseCookies(request.header('cookie'))[this.cookieName] ?? null);
  }

  private async loadSid(sid: string | null): Promise<WebSession> {
    if (sid && SID.test(sid)) {
      const state = await this.stateStore.get(webKey(sid));
      if (isObject(state)) {
        return new WebSession(this, sid, {
          sessions: isObject(state.sessions) ? (state.sessions as WebState['sessions']) : {},
          transactions: isObject(state.transactions) ? (state.transactions as WebState['transactions']) : {},
          ...(typeof state.expectedAdminUserId === 'string' ? { expectedAdminUserId: state.expectedAdminUserId } : {}),
        });
      }
    }

    return new WebSession(this, null, { sessions: {}, transactions: {} });
  }

  private prunePending(state: WebState): void {
    const now = this.client.now();
    const entries = Object.entries(state.transactions)
      .filter(([, transaction]) => now - Number(transaction.createdAt ?? 0) <= 600)
      .sort(([, a], [, b]) => b.createdAt - a.createdAt)
      .slice(0, MAX_PENDING - 1);
    state.transactions = Object.fromEntries(entries);
  }

  private hasAdminAccess(profile: BahariProfile): boolean {
    const access = profile.admin_access;
    if (!isObject(access)) {
      return false;
    }
    const platform = this.client.config.platform;

    return typeof access.platform !== 'string' || platform === null || access.platform === platform;
  }

  private enabled(kind: string | null | undefined): kind is Kind {
    return (kind === 'client' || kind === 'admin') && this.kinds[kind] !== undefined;
  }

  private enabledKinds(): Kind[] {
    return (['client', 'admin'] as const).filter((kind) => this.enabled(kind));
  }

  private origin(request: AuthRequest): string {
    return this.baseUrl ?? request.url.origin;
  }

  /** Blocks cross-site form posts (Origin / Sec-Fetch-Site). Requests without these headers are allowed. */
  private sameOrigin(request: AuthRequest): boolean {
    const origin = request.header('origin');
    if (origin !== null && origin !== this.origin(request)) {
      return false;
    }

    return request.header('sec-fetch-site') !== 'cross-site';
  }
}

export function createBahariAuth(options: BahariAuthOptions): BahariAuth {
  return new BahariAuth(options);
}

function notAllowed(allow: string): AuthResult {
  return text(405, 'Method not allowed.', { Allow: allow });
}

function describe(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}
