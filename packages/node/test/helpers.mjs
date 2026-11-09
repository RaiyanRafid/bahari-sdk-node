import { generateKeyPairSync, sign } from 'node:crypto';
import { BahariClient, MemoryCache } from '../dist/esm/index.js';

export const ISSUER = 'https://accounts.example.test';
export const SUBJECT = '0198a6c1-1111-7000-8000-000000000001';
export const CUSTOMER = '0198a6c1-2222-7000-8000-000000000002';
export const OTHER = '0198a6c1-3333-7000-8000-000000000003';
export const ADMIN_ID = '0198a6c1-4444-7000-8000-000000000004';

export const silent = { warn() {}, info() {} };

/** A real RS256 key pair and its public JWK. */
export function keyPair(kid = 'k1') {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const { n, e } = publicKey.export({ format: 'jwk' });

  return { privateKey, jwk: { kty: 'RSA', use: 'sig', alg: 'RS256', kid, n, e } };
}

export const KEY = keyPair('k1');

const now = () => Math.floor(Date.now() / 1000);

export function jwt(claims = {}, { key = KEY, header = {} } = {}) {
  const head = { alg: 'RS256', typ: 'JWT', kid: key.jwk.kid, ...header };
  const payload = { iss: ISSUER, aud: ['client-1'], sub: SUBJECT, iat: now(), exp: now() + 900, ...claims };
  for (const [name, value] of Object.entries(payload)) {
    if (value === undefined) delete payload[name];
  }
  const input = `${Buffer.from(JSON.stringify(head)).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;

  return `${input}.${sign('RSA-SHA256', Buffer.from(input), key.privateKey).toString('base64url')}`;
}

export function discovery(admin = 'https://admin.example.test') {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/oauth/authorize`,
    token_endpoint: `${ISSUER}/oauth/token`,
    profile_endpoint: `${ISSUER}/oauth/user`,
    jwks_uri: `${ISSUER}/oauth/jwks`,
    revocation_endpoint: `${ISSUER}/oauth/revoke`,
    end_session_endpoint: `${ISSUER}/oauth/logout`,
    client: { wallet_url: `${ISSUER}/dashboard/wallet` },
    admin: {
      panel_url: `${admin}/admin`,
      authorize_endpoint: `${admin}/admin-sso/authorize`,
      exchange_endpoint: `${ISSUER}/api/v1/admin-sso/exchange`,
      session_endpoint: `${ISSUER}/api/v1/admin-sso/session`,
      revoke_endpoint: `${ISSUER}/api/v1/admin-sso/revoke`,
      navigation_endpoint: `${ISSUER}/api/v1/admin-sso/navigation`,
    },
    api: { base_url: `${ISSUER}/api/v1`, platform_navigation: `${ISSUER}/api/v1/platform-navigation` },
  };
}

export function profile(overrides = {}) {
  return { id: SUBJECT, name: 'Rafi', email: 'rafi@example.test', status: 'active', customer: { id: CUSTOMER }, ...overrides };
}

export function adminProfile(overrides = {}) {
  return { id: ADMIN_ID, name: 'Rafi Admin', email: 'admin@example.test', platform: 'reseller', role: 'ADMIN', user_id: SUBJECT, session_token: 's'.repeat(64), ...overrides };
}

export function reply(data, status = 200, headers = {}) {
  return { status, body: typeof data === 'string' ? data : JSON.stringify(data), headers: { 'content-type': 'application/json', ...headers } };
}

/**
 * A fake fetch. routes: "METHOD url-without-query" => reply | (request) => reply. Unknown routes throw like a network
 * failure. Every request is recorded in .sent.
 */
export class FakeFetch {
  constructor(routes = {}) {
    this.routes = routes;
    this.sent = [];
    this.fetch = async (url, init = {}) => {
      const request = { method: init.method ?? 'GET', url, headers: { ...(init.headers ?? {}) }, body: init.body ?? null, redirect: init.redirect };
      this.sent.push(request);
      const route = this.routes[`${request.method} ${url.split('?')[0]}`];
      if (route === undefined) {
        throw new TypeError(`fetch failed: unexpected request ${request.method} ${url}`);
      }
      const result = typeof route === 'function' ? await route(request) : route;

      return new Response(result.status === 204 ? null : result.body, { status: result.status, headers: result.headers });
    };
  }

  calls(method, url) {
    return this.sent.filter((request) => request.method === method && request.url.split('?')[0] === url);
  }
}

export function client(fake, { cache, config = {}, ...options } = {}) {
  return new BahariClient(
    { issuer: ISSUER, clientId: 'client-1', clientSecret: 'secret-1', platform: 'reseller', ...config },
    { fetch: fake.fetch, cache: cache ?? new MemoryCache(), sdk: '@bahari/node/0.1.0', logger: silent, ...options },
  );
}

/** Routes for a full customer + admin setup. */
export function standardRoutes({ adminData = adminProfile(), customer = profile(), tokenNonce } = {}) {
  return {
    [`GET ${ISSUER}/.well-known/bahari-configuration`]: reply(discovery()),
    [`GET ${ISSUER}/oauth/jwks`]: reply({ keys: [KEY.jwk] }),
    [`GET ${ISSUER}/oauth/user`]: () => reply({ data: typeof customer === 'function' ? customer() : customer }),
    [`POST ${ISSUER}/oauth/token`]: (request) => {
      const body = new URLSearchParams(request.body);
      if (body.get('grant_type') === 'client_credentials') {
        return reply({ access_token: 'machine', expires_in: 3600 });
      }

      return reply({ access_token: 'access-1', refresh_token: 'refresh-1', expires_in: 3600, id_token: jwt({ nonce: tokenNonce?.() }) });
    },
    [`POST ${ISSUER}/api/v1/admin-sso/exchange`]: () => reply({ data: typeof adminData === 'function' ? adminData() : adminData }),
    [`POST ${ISSUER}/api/v1/admin-sso/session`]: () => reply({ data: typeof adminData === 'function' ? adminData() : adminData }),
    [`POST ${ISSUER}/api/v1/admin-sso/revoke`]: reply({ data: { revoked: true } }),
    [`POST ${ISSUER}/oauth/revoke`]: reply({}),
  };
}
