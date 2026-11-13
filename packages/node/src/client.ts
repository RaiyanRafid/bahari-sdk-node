import { createHash } from 'node:crypto';
import { type BahariCache, MemoryCache } from './cache.js';
import { type BahariConfigInput, Config } from './config.js';
import { Discovery, type DiscoveryDocument } from './discovery.js';
import { AccessDeniedError, BahariError, HttpError } from './errors.js';
import { type FetchLike, HttpResponse } from './http.js';
import {
  type BahariProfile,
  type Identity,
  type Kind,
  KINDS,
  type LoginRequest,
  type LoginTransaction,
  type Logger,
  type PlatformBranding,
  type Role,
  type SdkStatus,
  type TokenClaims,
  type Tokens,
} from './types.js';
import { TokenVerifier } from './verifier.js';
import { base64Url, buildQuery, isEmail, isObject, isUuid, randomHex, sha256Hex, unixNow } from './util.js';
import { PACKAGE, SDK, VERSION } from './version.js';

type MaybePromise<T> = T | Promise<T>;

export interface BahariClientOptions {
  /** Defaults to the global fetch. Requests never follow redirects. */
  fetch?: FetchLike;
  /** Discovery, JWKS and machine tokens. Defaults to an in-process MemoryCache. */
  cache?: BahariCache;
  /** Sent as X-Bahari-SDK so Bahari can tell you when the package is outdated. Default "@bahari/node/0.4.0". */
  sdk?: string;
  /** Encrypts cached machine tokens (recommended with a shared cache). */
  seal?: (value: string) => MaybePromise<string>;
  unseal?: (value: string) => MaybePromise<string>;
  /** Receives the outdated / unsupported SDK warning (at most once per process). Default console. */
  logger?: Logger;
  /** Request timeout in milliseconds. Default 10000. */
  timeout?: number;
  /** Clock in unix seconds (tests). */
  now?: () => number;
}

export interface NavigationResult {
  [key: string]: unknown;
}

const warned = new Set<string>();

/**
 * Bahari Accounts for one app. Only the issuer and the client credentials are configured; every endpoint, including
 * the admin host, comes from /.well-known/bahari-configuration, so Bahari can move domains without app changes.
 *
 * Kinds: "client" signs in customers with OIDC authorization code + PKCE. "admin" signs in platform administrators
 * through Bahari's admin SSO and a server-to-server exchange.
 */
export class BahariClient {
  static readonly KINDS = KINDS;

  readonly config: Config;

  private readonly fetcher: FetchLike;

  private readonly cache: BahariCache;

  private readonly sdk: string;

  private readonly logger: Logger;

  private readonly timeout: number;

  private readonly clock: () => number;

  private memo: { discovery: Discovery; until: number } | null = null;

  private loading: Promise<Discovery> | null = null;

  private status: SdkStatus | null = null;

  private tokenVerifier: TokenVerifier | null = null;

  constructor(
    config: Config | BahariConfigInput,
    private readonly options: BahariClientOptions = {},
  ) {
    this.config = config instanceof Config ? config : new Config(config);
    const globalFetch = (globalThis as { fetch?: FetchLike }).fetch;
    this.fetcher = options.fetch ?? ((input, init) => {
      if (!globalFetch) {
        throw new BahariError('No fetch implementation: use Node 18+ or pass options.fetch.');
      }

      return globalFetch(input, init);
    });
    this.cache = options.cache ?? new MemoryCache();
    this.sdk = options.sdk ?? SDK;
    this.logger = options.logger ?? console;
    this.timeout = options.timeout ?? 10_000;
    this.clock = options.now ?? unixNow;
  }

  /** Current unix time in seconds (the injected clock in tests). */
  now(): number {
    return this.clock();
  }

  /**
   * The discovery document: cached for the configured TTL, then the last good copy (up to a week) if Bahari is
   * unreachable, and finally the long-standing default endpoints.
   */
  async discovery(): Promise<Discovery> {
    if (this.memo && this.memo.until > this.now()) {
      return this.memo.discovery;
    }
    if (!this.loading) {
      this.loading = this.loadDiscovery().finally(() => {
        this.loading = null;
      });
    }

    return this.loading;
  }

  private async loadDiscovery(): Promise<Discovery> {
    const issuer = this.config.issuer;
    const key = `bahari:discovery:${sha256Hex(issuer)}`;
    const cached = await this.cache.get(key);
    if (isObject(cached)) {
      return this.remember(new Discovery(cached, cached.issuer === issuer), Math.min(60, this.config.discoveryTtl));
    }
    try {
      const data = (await this.send('GET', `${issuer}/.well-known/bahari-configuration`)).json();
      if (isObject(data) && data.issuer === issuer) {
        await this.cache.set(key, data, this.config.discoveryTtl);
        await this.cache.set(`${key}:last-good`, data, 604_800);

        return this.remember(new Discovery(data), this.config.discoveryTtl);
      }
    } catch {
      // Fall through to the last good copy or the defaults.
    }
    const last = await this.cache.get(`${key}:last-good`);
    const discovery = isObject(last) ? new Discovery(last) : Discovery.fallback(this.config);
    await this.cache.set(key, discovery.toJSON(), 60);

    return this.remember(discovery, 60);
  }

  private remember(discovery: Discovery, seconds: number): Discovery {
    this.memo = { discovery, until: this.now() + seconds };

    return discovery;
  }

  /**
   * Starts a sign-in. Store request.transaction in the server-side session under request.state, then redirect the
   * browser to request.url.
   */
  async beginLogin(kind: Kind, redirectUri: string, options: { loginHint?: string | null; prompt?: 'create' | 'login' | null } = {}): Promise<LoginRequest> {
    assertKind(kind);
    if (!this.config.configured()) {
      throw new BahariError('Bahari sign-in is not configured: set the client ID and secret.');
    }
    const state = randomHex(32);
    const nonce = randomHex(32);
    const verifier = randomHex(32);
    const parameters: Record<string, string> = {
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      state,
      code_challenge: base64Url(createHash('sha256').update(verifier).digest()),
    };
    if (kind === 'client') {
      Object.assign(parameters, { response_type: 'code', scope: this.config.scopes, nonce, code_challenge_method: 'S256' });
      // "create" opens Bahari registration first, then continues the sign-in.
      if (options.prompt === 'create' || options.prompt === 'login') {
        parameters.prompt = options.prompt;
      }
    }
    if (typeof options.loginHint === 'string' && options.loginHint.length <= 255 && /^[^\s@]+@[^\s@]+$/.test(options.loginHint)) {
      parameters.login_hint = options.loginHint;
    }
    const endpoint = (await this.discovery()).url(kind === 'admin' ? 'admin.authorize_endpoint' : 'authorization_endpoint');

    return {
      url: `${endpoint}${endpoint.includes('?') ? '&' : '?'}${buildQuery(parameters)}`,
      state,
      transaction: { kind, nonce, verifier, redirectUri, createdAt: this.now() },
    };
  }

  /** Finishes a sign-in with the transaction saved by beginLogin() and the code from the callback. */
  async completeLogin(transaction: LoginTransaction, code: string): Promise<Identity> {
    const kind = transaction?.kind;
    assertKind(kind);
    if (!Number.isInteger(transaction.createdAt) || this.now() - transaction.createdAt > 600) {
      throw new BahariError('The sign-in expired. Start again.');
    }
    const exchange = { code, code_verifier: transaction.verifier, redirect_uri: transaction.redirectUri };
    if (kind === 'admin') {
      const profile = await this.machine('admin.exchange_endpoint', exchange);
      const tokens: Tokens = { session_token: String(profile.session_token ?? '') };
      delete profile.session_token;
      checkIdentity(profile);
      this.authorizeAdmin(profile);

      return { kind: 'admin', subject: profile.id as string, tokens, profile: profile as BahariProfile, accessExpiresIn: null, tokensChanged: false };
    }
    const tokens = await this.token({ ...exchange, grant_type: 'authorization_code' });
    const claims = await this.verifier().verify(String(tokens.id_token ?? ''), { nonce: transaction.nonce });
    const profile = await this.profile(String(tokens.access_token), claims.sub);
    checkIdentity(profile);

    return { kind: 'client', subject: claims.sub, tokens, profile, accessExpiresIn: lifetime(tokens), tokensChanged: true };
  }

  /**
   * Re-checks a stored session with Bahari (call on each request or every few minutes). Client access tokens are
   * rotated when they expire within 30 seconds; store the returned tokens when tokensChanged is true.
   *
   * @throws AccessDeniedError when the session must end.
   */
  async refresh(kind: Kind, tokens: Tokens, subject: string, accessExpiresIn: number | null = null): Promise<Identity> {
    assertKind(kind);
    try {
      if (kind === 'admin') {
        const profile = await this.machine('admin.session_endpoint', { session_token: String(tokens.session_token ?? '') });
        delete profile.session_token;
        if (profile.id !== subject) {
          throw new AccessDeniedError('The admin session belongs to another account.');
        }
        this.authorizeAdmin(profile);

        return { kind: 'admin', subject, tokens, profile: profile as BahariProfile, accessExpiresIn: null, tokensChanged: false };
      }
      let current = tokens;
      let changed = false;
      let expiresIn = accessExpiresIn;
      if (accessExpiresIn !== null && accessExpiresIn !== undefined && accessExpiresIn < 30) {
        current = await this.token({ grant_type: 'refresh_token', refresh_token: String(tokens.refresh_token ?? '') });
        const claims = await this.verifier().verify(String(current.id_token ?? ''));
        if (claims.sub !== subject) {
          throw new AccessDeniedError('The identity changed during refresh.');
        }
        changed = true;
        expiresIn = lifetime(current);
      }
      const profile = await this.profile(String(current.access_token ?? ''), subject);

      return { kind: 'client', subject, tokens: current, profile, accessExpiresIn: expiresIn ?? null, tokensChanged: changed };
    } catch (error) {
      if (error instanceof HttpError && [400, 401, 403].includes(error.status)) {
        throw new AccessDeniedError('Bahari ended this session.', { cause: error });
      }
      throw error;
    }
  }

  /** Ends the session at Bahari (admin session or client tokens). */
  async revoke(kind: Kind, tokens: Tokens): Promise<void> {
    assertKind(kind);
    if (kind === 'admin') {
      await this.machine('admin.revoke_endpoint', { session_token: String(tokens.session_token ?? '') });

      return;
    }
    const url = (await this.discovery()).url('revocation_endpoint');
    for (const type of ['refresh_token', 'access_token'] as const) {
      if (tokens[type] !== undefined && tokens[type] !== null) {
        await this.form(url, { token: tokens[type], token_type_hint: type, client_id: this.config.clientId, client_secret: this.config.clientSecret });
      }
    }
  }

  /**
   * Where to send the browser after the local logout: Bahari's logout for customers, the admin panel for admins.
   * Pass the customer's id_token: with it Bahari signs out at once and returns to the app (no confirmation page).
   */
  async logoutUrl(kind: Kind, postLogoutRedirect: string, idTokenHint?: string | null): Promise<string> {
    assertKind(kind);
    const discovery = await this.discovery();
    if (kind === 'admin') {
      return discovery.url('admin.panel_url');
    }

    const parameters: Record<string, string> = { client_id: this.config.clientId, post_logout_redirect_uri: postLogoutRedirect };
    if (idTokenHint) {
      parameters.id_token_hint = idTokenHint;
    }

    return `${discovery.url('end_session_endpoint')}?${buildQuery(parameters)}`;
  }

  /**
   * The person's role in this app: SUPER_ADMIN, ADMIN or USER. Admin sessions carry their role; a customer session
   * is USER unless Bahari reports admin access to this platform (then send them on to admin sign-in).
   */
  role(identity: Pick<Identity, 'kind' | 'profile'>): Role {
    const profile = identity.profile ?? ({} as BahariProfile);
    let role: unknown = 'USER';
    if (identity.kind === 'admin') {
      role = profile.role ?? 'ADMIN';
    } else {
      const access = profile.admin_access;
      if (isObject(access) && access.platform === this.config.platform && (access.role === 'ADMIN' || access.role === 'SUPER_ADMIN')) {
        role = access.role;
      }
    }

    return role === 'SUPER_ADMIN' || role === 'ADMIN' ? role : 'USER';
  }

  /** True for an administrator session of this app (not for a customer who merely could become one). */
  isAdmin(identity: Pick<Identity, 'kind' | 'profile'>): boolean {
    return identity.kind === 'admin' && this.role(identity) !== 'USER';
  }

  /**
   * The Bahari account a back-channel logout is about: the customer subject, or the linked user of an admin session.
   */
  static linkedUserId(identity: Pick<Identity, 'kind' | 'subject' | 'profile'>): string {
    return identity.kind === 'admin' ? String(identity.profile?.user_id ?? '') : identity.subject;
  }

  /**
   * The app's branding, access mode, maintenance state and support contact from Bahari (Connected apps › Branding /
   * Access). Public, cached for `ttl` seconds; the last good copy is used when Bahari cannot be reached.
   */
  async branding(platform: string | null = null, ttl = 60): Promise<PlatformBranding> {
    const key = platform ?? this.config.platform;
    if (typeof key !== 'string' || !/^[a-z0-9_-]{1,80}$/.test(key)) {
      throw new BahariError('Set the platform key (BAHARI_PLATFORM_KEY) to read branding.');
    }
    const defaults: PlatformBranding = {
      name: null, access_mode: 'hybrid', logo_url: null, logo_light_url: null, logo_dark_url: null, favicon_url: null, brand_color: null,
      maintenance: { enabled: false, message: null }, support: { email: null, phone: null, url: null },
    };
    const cacheKey = `bahari:branding:${sha256Hex(`${this.config.issuer}|${key}`)}`;
    const cached = await this.cache.get(cacheKey);
    if (isObject(cached)) {
      return { ...defaults, ...(cached as Partial<PlatformBranding>) };
    }
    const template = String((await this.discovery()).get('api.platform_branding') ?? `${this.config.issuer}/api/v1/platform-branding/{key}`);
    try {
      const data = (await this.send('GET', template.replace('{key}', encodeURIComponent(key)), {}, null, true)).json('data');
      if (isObject(data)) {
        await this.cache.set(cacheKey, data, Math.max(1, ttl));
        await this.cache.set(`${cacheKey}:last-good`, data, 604_800);

        return { ...defaults, ...(data as Partial<PlatformBranding>) };
      }
    } catch {
      // Fall back to the last good copy.
    }
    const last = await this.cache.get(`${cacheKey}:last-good`);

    return { ...defaults, ...(isObject(last) ? (last as Partial<PlatformBranding>) : {}) };
  }

  /** Whether Bahari has this app in maintenance mode, with the message to show in a banner. */
  async maintenance(platform: string | null = null): Promise<{ enabled: boolean; message: string | null }> {
    const maintenance = (await this.branding(platform)).maintenance ?? { enabled: false, message: null };

    return { enabled: Boolean(maintenance.enabled), message: typeof maintenance.message === 'string' ? maintenance.message : null };
  }

  /**
   * The platform switcher for the signed-in person. For customers the wallet link opens Bahari's wallet for this
   * platform.
   */
  async navigation(kind: Kind, tokens: Tokens, walletReturnTo: string | null = null): Promise<NavigationResult> {
    assertKind(kind);
    if (kind === 'admin') {
      return this.machine('admin.navigation_endpoint', { session_token: String(tokens.session_token ?? '') });
    }
    const url = (await this.discovery()).url('api.platform_navigation');
    const navigation = (await this.send('GET', url, { Authorization: `Bearer ${tokens.access_token ?? ''}` }, null, true)).json('data');
    if (isObject(navigation) && isObject(navigation.wallet)) {
      navigation.wallet.url = await this.walletUrl(walletReturnTo);
    }

    return isObject(navigation) ? navigation : {};
  }

  /** Saves the customer's pinned platforms. Returns Bahari's response so validation errors (422) can be shown. */
  async updatePinned(tokens: Tokens, keys: string[]): Promise<HttpResponse> {
    const url = (await this.discovery()).url('api.platform_navigation');
    const response = await this.send(
      'PUT',
      url,
      { Authorization: `Bearer ${tokens.access_token ?? ''}`, 'Content-Type': 'application/json' },
      JSON.stringify({ pinned_keys: Array.from(keys) }),
    );
    if (!response.ok && response.status !== 422) {
      throw new HttpError(response, url);
    }

    return response;
  }

  /**
   * Verifies a back-channel logout token. Returns its claims; end every local customer session of claims.sub, once
   * per claims.jti.
   */
  async verifyLogoutToken(token: string): Promise<TokenClaims> {
    return this.verifier().verify(token, { logout: true });
  }

  /** Verifies an ID token (and optionally its nonce). */
  async verifyIdToken(token: string, nonce?: string | null): Promise<TokenClaims> {
    return this.verifier().verify(token, { nonce });
  }

  /** A URL from discovery, such as client.wallet_url, client.profile_url, admin.panel_url or admin.billing_url. */
  async url(name: string, query: Record<string, unknown> = {}): Promise<string> {
    const url = (await this.discovery()).url(name);
    const search = buildQuery(query);

    return Object.keys(query).length === 0 ? url : `${url}${url.includes('?') ? '&' : '?'}${search}`;
  }

  async walletUrl(returnTo: string | null = null, amount: string | null = null): Promise<string> {
    const query: Record<string, string> = {};
    if (this.config.platform) {
      query.platform = this.config.platform;
    }
    if (returnTo) {
      query.return_to = returnTo;
    }
    if (amount) {
      query.amount = amount;
    }

    return this.url('client.wallet_url', query);
  }

  checkoutOptions(externalUserId: string): Promise<Record<string, any>> {
    return this.api('GET', `platform-wallets/${encodeURIComponent(externalUserId)}/checkout-options`, {}, 'wallet:read');
  }

  startTopUp(externalUserId: string, topUp: Record<string, unknown>): Promise<Record<string, any>> {
    return this.api('POST', `platform-wallets/${encodeURIComponent(externalUserId)}/top-ups`, topUp, 'wallet:debit');
  }

  topUp(externalUserId: string, reference: string): Promise<Record<string, any>> {
    return this.api('GET', `platform-wallets/${encodeURIComponent(externalUserId)}/top-ups/${encodeURIComponent(reference)}`, {}, 'wallet:read');
  }

  /**
   * Calls a platform API endpoint with this app's machine token (client credentials). path is relative to the API
   * base URL, for example "platform-wallets/123/debits".
   */
  // ---------------------------------------------------------------- billing (features "Invoices" / "Subscriptions")
  // The app sets its prices; Bahari invoices, takes payment and renews. `reference` is your own UUID (idempotent).
  // Answers are { data, payment }; send the customer to data.checkout_url (or data.open_invoice.checkout_url)
  // unless you paid with pay: 'wallet' (feature "Charge without confirmation").

  createInvoice(invoice: Record<string, unknown>): Promise<Record<string, any>> {
    return this.api('POST', 'platform-billing/invoices', invoice, 'billing');
  }

  invoice(reference: string): Promise<Record<string, any>> {
    return this.api('GET', `platform-billing/invoices/${encodeURIComponent(reference)}`, {}, 'billing');
  }

  voidInvoice(reference: string): Promise<Record<string, any>> {
    return this.api('POST', `platform-billing/invoices/${encodeURIComponent(reference)}/void`, {}, 'billing');
  }

  createSubscription(subscription: Record<string, unknown>): Promise<Record<string, any>> {
    return this.api('POST', 'platform-billing/subscriptions', subscription, 'billing');
  }

  subscription(reference: string): Promise<Record<string, any>> {
    return this.api('GET', `platform-billing/subscriptions/${encodeURIComponent(reference)}`, {}, 'billing');
  }

  /** Changes plan_name, amount or cycle from the next renewal invoice. */
  updateSubscription(reference: string, changes: Record<string, unknown>): Promise<Record<string, any>> {
    return this.api('PATCH', `platform-billing/subscriptions/${encodeURIComponent(reference)}`, changes, 'billing');
  }

  cancelSubscription(reference: string, when: 'period_end' | 'now' = 'period_end'): Promise<Record<string, any>> {
    return this.api('POST', `platform-billing/subscriptions/${encodeURIComponent(reference)}/cancel`, { when }, 'billing');
  }

  resumeSubscription(reference: string): Promise<Record<string, any>> {
    return this.api('POST', `platform-billing/subscriptions/${encodeURIComponent(reference)}/resume`, {}, 'billing');
  }

  customerSubscriptions(userId: string): Promise<Record<string, any>> {
    return this.api('GET', `platform-billing/customers/${encodeURIComponent(userId)}/subscriptions`, {}, 'billing');
  }

  async api(method: string, path: string, data: Record<string, unknown> = {}, scope = 'identity:lookup'): Promise<Record<string, any>> {
    const verb = method.toUpperCase();
    let url = `${(await this.discovery()).url('api.base_url').replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
    const body = verb === 'GET' ? null : JSON.stringify(data);
    if (verb === 'GET' && Object.keys(data).length > 0) {
      url += `${url.includes('?') ? '&' : '?'}${buildQuery(data)}`;
    }
    const response = await this.send(verb, url, { Authorization: `Bearer ${await this.machineToken(scope)}`, 'Content-Type': 'application/json' }, body, true);
    const json = response.json();

    return isObject(json) ? json : Array.isArray(json) ? { ...json } : {};
  }

  /** "ok", "outdated", "unsupported" or "unknown" from the last Bahari response, or null before any request. */
  sdkStatus(): SdkStatus | null {
    return this.status;
  }

  /** The issuer's JSON Web Key Set (cached for 300 seconds). */
  async jwks(fresh = false): Promise<Record<string, unknown>> {
    const url = (await this.discovery()).url('jwks_uri');
    const key = `bahari:jwks:${sha256Hex(url)}`;
    const cached = fresh ? undefined : await this.cache.get(key);
    if (isObject(cached)) {
      return cached;
    }
    const json = (await this.send('GET', url, {}, null, true)).json();
    const jwks = isObject(json) ? json : {};
    await this.cache.set(key, jwks, 300);

    return jwks;
  }

  verifier(): TokenVerifier {
    if (!this.tokenVerifier) {
      const host = this;
      this.tokenVerifier = new TokenVerifier({
        issuer: this.config.issuer,
        clientId: this.config.clientId,
        jwks: (fresh) => host.jwks(fresh),
        now: () => host.now(),
      });
    }

    return this.tokenVerifier;
  }

  /** The package and version this client reports, for example "@bahari/node/0.4.0". */
  get sdkHeader(): string {
    return this.sdk;
  }

  private async token(data: Record<string, unknown>): Promise<Tokens> {
    const url = (await this.discovery()).url('token_endpoint');
    const response = await this.form(url, { ...data, client_id: this.config.clientId, client_secret: this.config.clientSecret });
    const tokens = response.json();
    if (!isObject(tokens) || typeof tokens.access_token !== 'string') {
      throw new BahariError('Bahari returned no access token.');
    }

    return tokens as Tokens;
  }

  private async profile(accessToken: string, subject: string): Promise<BahariProfile> {
    const url = (await this.discovery()).url('profile_endpoint');
    const profile = (await this.send('GET', url, { Authorization: `Bearer ${accessToken}` }, null, true)).json('data');
    if (!isObject(profile) || profile.id !== subject || profile.status !== 'active' || !isObject(profile.customer) || !isUuid(profile.customer.id)) {
      throw new AccessDeniedError('The Bahari account is unavailable.');
    }

    return profile as BahariProfile;
  }

  private async machine(endpoint: string, data: Record<string, unknown>): Promise<Record<string, unknown>> {
    const url = (await this.discovery()).url(endpoint);
    const call = async (): Promise<HttpResponse> =>
      this.send('POST', url, { Authorization: `Bearer ${await this.machineToken('identity:lookup')}`, 'Content-Type': 'application/json' }, JSON.stringify(data));
    let response = await call();
    if (response.status === 401) {
      await this.cache.delete(this.machineKey('identity:lookup'));
      response = await call();
    }
    if (!response.ok) {
      throw new HttpError(response, url);
    }
    const result = response.json('data');

    return isObject(result) ? result : {};
  }

  private async machineToken(scope: string): Promise<string> {
    const key = this.machineKey(scope);
    const sealed = await this.cache.get(key);
    if (typeof sealed === 'string') {
      return this.options.unseal ? await this.options.unseal(sealed) : sealed;
    }
    const tokens = await this.token({ grant_type: 'client_credentials', scope });
    const token = tokens.access_token as string;
    const expiresIn = Math.trunc(Number(tokens.expires_in ?? 600)) || 0;
    await this.cache.set(key, this.options.seal ? await this.options.seal(token) : token, Math.max(30, Math.min(600, expiresIn - 60)));

    return token;
  }

  private machineKey(scope: string): string {
    return `bahari:machine:${sha256Hex(`${this.config.clientId}\0${this.config.clientSecret}\0${scope}`)}`;
  }

  private form(url: string, data: Record<string, unknown>): Promise<HttpResponse> {
    return this.send('POST', url, { 'Content-Type': 'application/x-www-form-urlencoded' }, buildQuery(data), true);
  }

  private async send(method: string, url: string, headers: Record<string, string> = {}, body: string | null = null, throwOnError = false): Promise<HttpResponse> {
    const all: Record<string, string> = { Accept: 'application/json', 'X-Bahari-SDK': this.sdk, ...headers };
    let raw: Response;
    try {
      raw = await this.fetcher(url, {
        method,
        headers: all,
        body: body ?? undefined,
        redirect: 'manual',
        signal: AbortSignal.timeout(this.timeout),
      });
    } catch (error) {
      throw new BahariError('Bahari Accounts could not be reached.', { cause: error });
    }
    const received: Record<string, string> = {};
    raw.headers.forEach((value, name) => {
      received[name.toLowerCase()] = value;
    });
    let text = '';
    try {
      text = await raw.text();
    } catch (error) {
      throw new BahariError('Bahari Accounts could not be reached.', { cause: error });
    }
    const response = new HttpResponse(raw.status, text, received);
    const status = response.header('X-Bahari-SDK-Status');
    if (status) {
      this.status = status;
      this.warnIfOutdated(status);
    }
    if (throwOnError && !response.ok) {
      throw new HttpError(response, url);
    }

    return response;
  }

  private warnIfOutdated(status: string): void {
    if ((status === 'outdated' || status === 'unsupported') && !warned.has(`${this.sdk}:${status}`)) {
      warned.add(`${this.sdk}:${status}`);
      const name = this.sdk.slice(0, this.sdk.lastIndexOf('/')) || PACKAGE;
      this.logger.warn(`Bahari reports ${this.sdk} as ${status}. Run: npm install ${name}@latest${name === PACKAGE ? '' : ` ${PACKAGE}@latest`}`, {
        sdk: this.sdk,
        status,
        version: VERSION,
      });
    }
  }

  private authorizeAdmin(profile: Record<string, unknown>): void {
    if (this.config.platform === null || profile.platform !== this.config.platform || !['ADMIN', 'SUPER_ADMIN'].includes(String(profile.role))) {
      throw new AccessDeniedError('Administration of this platform is not authorized.');
    }
  }
}

/** Forgets which SDK warnings were already logged in this process (tests). */
export function resetSdkWarnings(): void {
  warned.clear();
}

function assertKind(kind: unknown): asserts kind is Kind {
  if (kind !== 'client' && kind !== 'admin') {
    throw new TypeError('Kind must be "client" or "admin".');
  }
}

function checkIdentity(profile: Record<string, unknown>): asserts profile is BahariProfile {
  if (!isUuid(profile.id) || !isEmail(profile.email) || typeof profile.name !== 'string') {
    throw new BahariError('Bahari returned an invalid identity.');
  }
}

function lifetime(tokens: Tokens): number {
  const expiresIn = Math.trunc(Number(tokens.expires_in ?? 900)) || 0;

  return Math.min(900, Math.max(1, expiresIn));
}

export type { DiscoveryDocument };
