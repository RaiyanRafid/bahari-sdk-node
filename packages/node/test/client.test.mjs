import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, test } from 'node:test';
import {
  AccessDeniedError,
  BahariClient,
  BahariError,
  Config,
  HttpError,
  InvalidTokenError,
  MemoryCache,
  resetSdkWarnings,
} from '../dist/esm/index.js';
import { ADMIN_ID, FakeFetch, ISSUER, KEY, OTHER, SUBJECT, adminProfile, client, discovery, jwt, keyPair, profile, reply } from './helpers.mjs';

const DISCOVERY = `GET ${ISSUER}/.well-known/bahari-configuration`;
const sha = (value) => createHash('sha256').update(value).digest('hex');

describe('BahariClient (ports ClientTest.php)', () => {
  test('admin login uses the admin host from discovery and sends the SDK header', async () => {
    resetSdkWarnings();
    const warnings = [];
    const fake = new FakeFetch({ [DISCOVERY]: reply(discovery('https://new-admin.example.test'), 200, { 'x-bahari-sdk-status': 'outdated' }) });
    const bahari = client(fake, { logger: { warn: (message) => warnings.push(message) } });
    const login = await bahari.beginLogin('admin', 'https://app.example.test/auth/admin/callback');

    assert.ok(login.url.startsWith('https://new-admin.example.test/admin-sso/authorize?'));
    const query = new URL(login.url).searchParams;
    assert.equal(query.get('state'), login.state);
    assert.equal(query.get('client_id'), 'client-1');
    assert.equal(query.get('redirect_uri'), 'https://app.example.test/auth/admin/callback');
    assert.equal(query.get('code_challenge'), createHash('sha256').update(login.transaction.verifier).digest('base64url'));
    assert.equal(query.get('response_type'), null);
    assert.equal(query.get('scope'), null);
    assert.equal(query.get('nonce'), null);
    assert.equal(fake.sent[0].headers['X-Bahari-SDK'], '@bahari/node/0.1.0');
    assert.equal(fake.sent[0].headers.Accept, 'application/json');
    assert.equal(fake.sent[0].redirect, 'manual');
    assert.equal(bahari.sdkStatus(), 'outdated');

    // The outdated warning is logged at most once per process, even for another client instance.
    await client(fake, { logger: { warn: (message) => warnings.push(message) } }).beginLogin('admin', 'https://app.example.test/cb');
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /@bahari\/node\/0\.1\.0 as outdated/);
  });

  test('discovery falls back to defaults and rejects a document for another issuer', async () => {
    const fake = new FakeFetch({ [DISCOVERY]: reply({ ...discovery('https://evil.example.test'), issuer: 'https://evil.example.test' }) });
    const bahari = client(fake, { config: { adminIssuer: 'https://admin-fallback.example.test' } });

    assert.equal((await bahari.discovery()).fromServer, false);
    assert.equal((await bahari.discovery()).url('admin.authorize_endpoint'), 'https://admin-fallback.example.test/admin-sso/authorize');
    assert.equal((await bahari.discovery()).url('token_endpoint'), `${ISSUER}/oauth/token`);
    assert.equal(await bahari.url('admin.profile_url'), 'https://admin-fallback.example.test/admin/profile');
    assert.equal(await bahari.url('client.applications_url'), `${ISSUER}/dashboard/applications`);
  });

  test('last good discovery is used when Bahari is unreachable', async () => {
    const cache = new MemoryCache();
    await client(new FakeFetch({ [DISCOVERY]: reply(discovery('https://moved-admin.example.test')) }), { cache }).discovery();
    await cache.delete(`bahari:discovery:${sha(ISSUER)}`);

    const bahari = client(new FakeFetch(), { cache });

    assert.equal(await bahari.url('admin.panel_url'), 'https://moved-admin.example.test/admin');
  });

  test('discovery is cached for the TTL and never follows redirects', async () => {
    const fake = new FakeFetch({ [DISCOVERY]: reply(discovery()) });
    const cache = new MemoryCache();
    await client(fake, { cache }).discovery();
    await client(fake, { cache }).discovery();
    assert.equal(fake.calls('GET', `${ISSUER}/.well-known/bahari-configuration`).length, 1);

    const redirecting = new FakeFetch({ [DISCOVERY]: { status: 302, body: '', headers: { location: 'https://evil.example.test/' } } });
    const bahari = client(redirecting);
    assert.equal((await bahari.discovery()).fromServer, false);
    assert.equal(redirecting.sent.length, 1);
  });

  test('client login verifies the id token, nonce and profile', async () => {
    const fake = new FakeFetch({
      [DISCOVERY]: reply(discovery()),
      [`GET ${ISSUER}/oauth/jwks`]: reply({ keys: [KEY.jwk] }),
      [`GET ${ISSUER}/oauth/user`]: reply({ data: profile({ admin_access: null }) }),
    });
    const bahari = client(fake);
    const login = await bahari.beginLogin('client', 'https://app.example.test/cb');
    const query = new URL(login.url).searchParams;
    assert.ok(login.url.startsWith(`${ISSUER}/oauth/authorize?`));
    assert.equal(query.get('response_type'), 'code');
    assert.equal(query.get('code_challenge_method'), 'S256');
    assert.equal(query.get('nonce'), login.transaction.nonce);
    assert.equal(query.get('scope'), 'openid profile email phone profile:read identity:read wallet:read platform:read');
    fake.routes[`POST ${ISSUER}/oauth/token`] = reply({ access_token: 'a', refresh_token: 'r', expires_in: 3600, id_token: jwt({ nonce: login.transaction.nonce }) });

    const identity = await bahari.completeLogin(login.transaction, 'code-1');

    assert.equal(identity.subject, SUBJECT);
    assert.equal(identity.accessExpiresIn, 900);
    assert.equal(identity.tokensChanged, true);
    assert.equal(identity.profile.email, 'rafi@example.test');
    const tokenRequest = new URLSearchParams(fake.calls('POST', `${ISSUER}/oauth/token`)[0].body);
    assert.equal(tokenRequest.get('grant_type'), 'authorization_code');
    assert.equal(tokenRequest.get('code_verifier'), login.transaction.verifier);
    assert.equal(tokenRequest.get('client_secret'), 'secret-1');
    assert.equal(fake.calls('GET', `${ISSUER}/oauth/user`)[0].headers.Authorization, 'Bearer a');

    fake.routes[`POST ${ISSUER}/oauth/token`] = reply({ access_token: 'a', id_token: jwt({ nonce: 'wrong' }) });
    await assert.rejects(bahari.completeLogin(login.transaction, 'code-2'), InvalidTokenError);
  });

  test('admin exchange requires an admin role for this platform', async () => {
    let data = adminProfile();
    const fake = new FakeFetch({
      [DISCOVERY]: reply(discovery()),
      [`POST ${ISSUER}/oauth/token`]: reply({ access_token: 'machine', expires_in: 3600 }),
      [`POST ${ISSUER}/api/v1/admin-sso/exchange`]: () => reply({ data }),
    });
    const bahari = client(fake);
    const login = await bahari.beginLogin('admin', 'https://app.example.test/cb');

    const identity = await bahari.completeLogin(login.transaction, 'code');
    assert.deepEqual(identity.tokens, { session_token: 's'.repeat(64) });
    assert.equal('session_token' in identity.profile, false);
    assert.equal(identity.profile.user_id, SUBJECT);
    assert.equal(identity.subject, ADMIN_ID);
    const exchange = fake.calls('POST', `${ISSUER}/api/v1/admin-sso/exchange`)[0];
    assert.equal(exchange.headers.Authorization, 'Bearer machine');
    assert.deepEqual(JSON.parse(exchange.body), { code: 'code', code_verifier: login.transaction.verifier, redirect_uri: 'https://app.example.test/cb' });
    assert.equal(new URLSearchParams(fake.calls('POST', `${ISSUER}/oauth/token`)[0].body).get('scope'), 'identity:lookup');

    data = adminProfile({ platform: 'sms' });
    await assert.rejects(bahari.completeLogin(login.transaction, 'code'), AccessDeniedError);
    data = adminProfile({ role: 'SUPPORT' });
    await assert.rejects(bahari.completeLogin(login.transaction, 'code'), AccessDeniedError);
    // The machine token is cached.
    assert.equal(fake.calls('POST', `${ISSUER}/oauth/token`).length, 1);
  });

  test('refresh rotates expiring tokens and rejects another subject', async () => {
    let subject = SUBJECT;
    const fake = new FakeFetch({
      [DISCOVERY]: reply(discovery()),
      [`GET ${ISSUER}/oauth/jwks`]: reply({ keys: [KEY.jwk] }),
      [`GET ${ISSUER}/oauth/user`]: reply({ data: profile() }),
      [`POST ${ISSUER}/oauth/token`]: () => reply({ access_token: 'new-a', refresh_token: 'new-r', expires_in: 600, id_token: jwt({ sub: subject }) }),
    });
    const bahari = client(fake);

    const fresh = await bahari.refresh('client', { access_token: 'a', refresh_token: 'r' }, SUBJECT, 300);
    assert.equal(fresh.tokensChanged, false);
    assert.equal(fake.calls('POST', `${ISSUER}/oauth/token`).length, 0);

    const rotated = await bahari.refresh('client', { access_token: 'a', refresh_token: 'r' }, SUBJECT, 10);
    assert.equal(rotated.tokensChanged, true);
    assert.equal(rotated.tokens.refresh_token, 'new-r');
    assert.equal(rotated.accessExpiresIn, 600);
    assert.equal(new URLSearchParams(fake.calls('POST', `${ISSUER}/oauth/token`)[0].body).get('refresh_token'), 'r');
    assert.equal(fake.sent.at(-1).headers.Authorization, 'Bearer new-a');

    subject = OTHER;
    await assert.rejects(bahari.refresh('client', { access_token: 'a', refresh_token: 'r' }, SUBJECT, 10), AccessDeniedError);
  });

  test('refresh turns 400/401/403 into AccessDenied and denies inactive accounts', async () => {
    let status = 401;
    let data = profile();
    const fake = new FakeFetch({ [DISCOVERY]: reply(discovery()), [`GET ${ISSUER}/oauth/user`]: () => reply({ data }, status) });
    const bahari = client(fake);
    await assert.rejects(bahari.refresh('client', { access_token: 'a' }, SUBJECT, 300), AccessDeniedError);
    status = 500;
    await assert.rejects(bahari.refresh('client', { access_token: 'a' }, SUBJECT, 300), (error) => error instanceof HttpError && !(error instanceof AccessDeniedError));
    status = 200;
    data = profile({ status: 'suspended' });
    await assert.rejects(bahari.refresh('client', { access_token: 'a' }, SUBJECT, 300), AccessDeniedError);
    data = profile({ customer: { id: 'not-a-uuid' } });
    await assert.rejects(bahari.refresh('client', { access_token: 'a' }, SUBJECT, 300), AccessDeniedError);
    data = profile({ admin_access: { platform: 'reseller', role: 'ADMIN', two_factor_ready: true } });
    const identity = await bahari.refresh('client', { access_token: 'a' }, SUBJECT, 300);
    assert.deepEqual(identity.profile.admin_access, { platform: 'reseller', role: 'ADMIN', two_factor_ready: true });
  });

  test('revoked admin session is access denied', async () => {
    const fake = new FakeFetch({
      [DISCOVERY]: reply(discovery()),
      [`POST ${ISSUER}/oauth/token`]: reply({ access_token: 'machine' }),
      [`POST ${ISSUER}/api/v1/admin-sso/session`]: reply({ message: 'revoked' }, 403),
    });

    await assert.rejects(client(fake).refresh('admin', { session_token: 'x' }, SUBJECT), AccessDeniedError);
  });

  test('admin refresh checks the subject and retries once with a new machine token on 401', async () => {
    let calls = 0;
    const fake = new FakeFetch({
      [DISCOVERY]: reply(discovery()),
      [`POST ${ISSUER}/oauth/token`]: () => reply({ access_token: `machine-${++calls}`, expires_in: 3600 }),
      [`POST ${ISSUER}/api/v1/admin-sso/session`]: (request) =>
        request.headers.Authorization === 'Bearer machine-1' ? reply({ message: 'expired' }, 401) : reply({ data: adminProfile() }),
    });
    const bahari = client(fake);
    const identity = await bahari.refresh('admin', { session_token: 'x' }, ADMIN_ID);
    assert.equal(identity.profile.user_id, SUBJECT);
    assert.equal('session_token' in identity.profile, false);
    assert.deepEqual(identity.tokens, { session_token: 'x' });
    assert.equal(calls, 2);
    await assert.rejects(bahari.refresh('admin', { session_token: 'x' }, OTHER), AccessDeniedError);
  });

  test('logout token and urls', async () => {
    const fake = new FakeFetch({ [DISCOVERY]: reply(discovery()), [`GET ${ISSUER}/oauth/jwks`]: reply({ keys: [KEY.jwk] }) });
    const bahari = client(fake);

    const claims = await bahari.verifyLogoutToken(jwt({ jti: 'j1', events: { 'http://schemas.openid.net/event/backchannel-logout': {} } }));
    assert.equal(claims.sub, SUBJECT);
    assert.equal(await bahari.logoutUrl('client', 'https://app.example.test/'), `${ISSUER}/oauth/logout?client_id=client-1&post_logout_redirect_uri=https%3A%2F%2Fapp.example.test%2F`);
    assert.equal(await bahari.logoutUrl('admin', 'https://app.example.test/'), 'https://admin.example.test/admin');
    assert.equal(await bahari.walletUrl('/dashboard'), `${ISSUER}/dashboard/wallet?platform=reseller&return_to=%2Fdashboard`);
    assert.equal(await bahari.url('admin.panel_url', { tab: 'users' }), 'https://admin.example.test/admin?tab=users');

    await assert.rejects(bahari.verifyLogoutToken(jwt({ jti: 'j2' })), InvalidTokenError);
    const event = { 'http://schemas.openid.net/event/backchannel-logout': {} };
    await assert.rejects(bahari.verifyLogoutToken(jwt({ events: event })), InvalidTokenError, 'jti is required');
    await assert.rejects(bahari.verifyLogoutToken(jwt({ jti: 'j3', nonce: 'n', events: event })), InvalidTokenError, 'nonce is not allowed');
    const old = Math.floor(Date.now() / 1000) - 400;
    await assert.rejects(bahari.verifyLogoutToken(jwt({ jti: 'j4', iat: old, exp: old + 3600, events: event })), InvalidTokenError, 'iat older than 300s');
  });

  test('issuer must be https (http only for localhost)', () => {
    assert.throws(() => new Config({ issuer: 'http://accounts.example.test', clientId: 'a', clientSecret: 'b' }), TypeError);
    assert.throws(() => new Config({ issuer: 'https://user:pass@accounts.example.test', clientId: 'a', clientSecret: 'b' }), TypeError);
    assert.throws(() => new Config({ issuer: 'https://accounts.example.test?x=1', clientId: 'a', clientSecret: 'b' }), TypeError);
    assert.throws(() => new Config({ issuer: 'ftp://accounts.example.test', clientId: 'a', clientSecret: 'b' }), TypeError);
    assert.equal(new Config({ issuer: 'http://localhost:8000/', clientId: 'a', clientSecret: 'b' }).issuer, 'http://localhost:8000');
    assert.equal(new Config({ issuer: 'https://accounts.example.test/', clientId: 'a', clientSecret: 'b' }).issuer, ISSUER);
    const env = Config.fromEnv({ BAHARI_CLIENT_ID: 'id', BAHARI_CLIENT_SECRET: 'secret', BAHARI_PLATFORM_KEY: 'reseller' });
    assert.equal(env.issuer, 'https://accounts.baharione.com');
    assert.equal(env.platform, 'reseller');
    assert.equal(env.discoveryTtl, 300);
    assert.equal(Config.fromEnv({}).configured(), false);
  });
});

describe('Token verification', () => {
  const routes = (keys) => ({ [DISCOVERY]: reply(discovery()), [`GET ${ISSUER}/oauth/jwks`]: () => reply({ keys: keys() }) });

  test('refetches the JWKS once for an unknown kid (key rotation)', async () => {
    const rotated = keyPair('k2');
    let keys = [KEY.jwk];
    const fake = new FakeFetch(routes(() => keys));
    const bahari = client(fake);
    await bahari.verifyIdToken(jwt());
    keys = [KEY.jwk, rotated.jwk];
    const claims = await bahari.verifyIdToken(jwt({}, { key: rotated }));
    assert.equal(claims.sub, SUBJECT);
    assert.equal(fake.calls('GET', `${ISSUER}/oauth/jwks`).length, 2);

    const unknown = keyPair('k3');
    await assert.rejects(bahari.verifyIdToken(jwt({}, { key: unknown })), /Invalid token signature/);
    assert.equal(fake.calls('GET', `${ISSUER}/oauth/jwks`).length, 3);
  });

  test('rejects forged signatures, other algorithms, missing kid and bad claims', async () => {
    const fake = new FakeFetch(routes(() => [KEY.jwk]));
    const bahari = client(fake);
    const forger = keyPair('k1');
    await assert.rejects(bahari.verifyIdToken(jwt({}, { key: forger })), InvalidTokenError);

    const [header, payload] = jwt().split('.');
    const none = `${Buffer.from(JSON.stringify({ alg: 'none', kid: 'k1' })).toString('base64url')}.${payload}.`;
    await assert.rejects(bahari.verifyIdToken(none), /algorithm/);
    const hs = `${Buffer.from(JSON.stringify({ alg: 'HS256', kid: 'k1' })).toString('base64url')}.${payload}.c2ln`;
    await assert.rejects(bahari.verifyIdToken(hs), /algorithm/);
    await assert.rejects(bahari.verifyIdToken(jwt({}, { header: { kid: undefined } })), /algorithm/);
    await assert.rejects(bahari.verifyIdToken(`${header}.${payload}`), /algorithm/);

    const now = Math.floor(Date.now() / 1000);
    await assert.rejects(bahari.verifyIdToken(jwt({ iss: 'https://evil.example.test' })), /claims/);
    await assert.rejects(bahari.verifyIdToken(jwt({ aud: 'other-client' })), /claims/);
    await assert.rejects(bahari.verifyIdToken(jwt({ sub: 'not-a-uuid' })), /claims/);
    await assert.rejects(bahari.verifyIdToken(jwt({ exp: undefined })), /claims/);
    await assert.rejects(bahari.verifyIdToken(jwt({ iat: undefined })), /claims/);
    await assert.rejects(bahari.verifyIdToken(jwt({ iat: now + 120 })), InvalidTokenError);
    await assert.rejects(bahari.verifyIdToken(jwt({ exp: now - 60 })), /expired/);
    // 30 seconds of leeway
    assert.equal((await bahari.verifyIdToken(jwt({ exp: now - 10, aud: 'client-1' }))).sub, SUBJECT);
    assert.equal((await bahari.verifyIdToken(jwt({ iat: now + 20 }))).sub, SUBJECT);
    // nonce: constant-time compare, required when expected
    assert.equal((await bahari.verifyIdToken(jwt({ nonce: 'n-1' }), 'n-1')).nonce, 'n-1');
    await assert.rejects(bahari.verifyIdToken(jwt(), 'n-1'), /nonce/);
  });
});

describe('Navigation, pinned platforms, wallet and platform APIs', () => {
  test('client navigation rewrites the wallet link; admin navigation uses the machine token', async () => {
    const fake = new FakeFetch({
      [DISCOVERY]: reply(discovery()),
      [`GET ${ISSUER}/api/v1/platform-navigation`]: reply({ data: { platforms: [{ key: 'reseller' }], wallet: { url: 'https://elsewhere.example.test', balance: '10.00' } } }),
      [`POST ${ISSUER}/oauth/token`]: reply({ access_token: 'machine', expires_in: 3600 }),
      [`POST ${ISSUER}/api/v1/admin-sso/navigation`]: reply({ data: { platforms: [{ key: 'reseller' }] } }),
    });
    const bahari = client(fake);
    const navigation = await bahari.navigation('client', { access_token: 'a' }, '/dashboard');
    assert.equal(navigation.wallet.url, `${ISSUER}/dashboard/wallet?platform=reseller&return_to=%2Fdashboard`);
    assert.equal(navigation.wallet.balance, '10.00');
    assert.equal(fake.calls('GET', `${ISSUER}/api/v1/platform-navigation`)[0].headers.Authorization, 'Bearer a');

    assert.deepEqual(await bahari.navigation('admin', { session_token: 's' }), { platforms: [{ key: 'reseller' }] });
    assert.deepEqual(JSON.parse(fake.calls('POST', `${ISSUER}/api/v1/admin-sso/navigation`)[0].body), { session_token: 's' });
  });

  test('updatePinned passes 422 through and throws on other errors', async () => {
    let status = 422;
    const fake = new FakeFetch({ [DISCOVERY]: reply(discovery()), [`PUT ${ISSUER}/api/v1/platform-navigation`]: () => reply({ message: 'invalid' }, status) });
    const bahari = client(fake);
    const response = await bahari.updatePinned({ access_token: 'a' }, ['reseller', 'sms']);
    assert.equal(response.status, 422);
    assert.deepEqual(JSON.parse(fake.sent.at(-1).body), { pinned_keys: ['reseller', 'sms'] });
    status = 500;
    await assert.rejects(bahari.updatePinned({ access_token: 'a' }, []), HttpError);
  });

  test('api() calls the API base URL with a machine token for the scope', async () => {
    const fake = new FakeFetch({
      [DISCOVERY]: reply(discovery()),
      [`POST ${ISSUER}/oauth/token`]: (request) => reply({ access_token: `machine:${new URLSearchParams(request.body).get('scope')}`, expires_in: 3600 }),
      [`GET ${ISSUER}/api/v1/platform-wallet-balances`]: reply({ data: [{ user: 'u1' }] }),
      [`POST ${ISSUER}/api/v1/platform-wallets/u1/debits`]: reply({ data: { id: 'd1' } }, 201),
    });
    const bahari = client(fake);
    const balances = await bahari.api('GET', '/platform-wallet-balances', { users: ['u1'], page: 2 });
    assert.deepEqual(balances, { data: [{ user: 'u1' }] });
    const sent = fake.calls('GET', `${ISSUER}/api/v1/platform-wallet-balances`)[0];
    assert.equal(sent.url, `${ISSUER}/api/v1/platform-wallet-balances?users%5B0%5D=u1&page=2`);
    assert.equal(sent.headers.Authorization, 'Bearer machine:identity:lookup');

    const debit = await bahari.api('post', 'platform-wallets/u1/debits', { amount: '5.00' }, 'wallet:debit');
    assert.deepEqual(debit, { data: { id: 'd1' } });
    const post = fake.calls('POST', `${ISSUER}/api/v1/platform-wallets/u1/debits`)[0];
    assert.equal(post.headers.Authorization, 'Bearer machine:wallet:debit');
    assert.deepEqual(JSON.parse(post.body), { amount: '5.00' });
  });

  test('billing helpers call the billing API with a billing machine token', async () => {
    const fake = new FakeFetch({
      [DISCOVERY]: reply(discovery()),
      [`POST ${ISSUER}/oauth/token`]: (request) => reply({ access_token: `machine:${new URLSearchParams(request.body).get('scope')}`, expires_in: 3600 }),
      [`POST ${ISSUER}/api/v1/platform-billing/invoices`]: reply({ data: { status: 'due', checkout_url: 'https://accounts.example.test/dashboard/checkout?invoice=1' }, payment: null }, 201),
      [`POST ${ISSUER}/api/v1/platform-billing/subscriptions/ref%2F1/cancel`]: (request) => reply({ data: { cancel_at_period_end: JSON.parse(request.body).when === 'period_end' } }),
      [`PATCH ${ISSUER}/api/v1/platform-billing/subscriptions/ref-2`]: (request) => reply({ data: JSON.parse(request.body) }),
    });
    const bahari = client(fake);
    const invoice = await bahari.createInvoice({ user_id: SUBJECT, reference: 'r1', items: [{ description: 'x', unit_price: '10.00' }] });
    assert.equal(invoice.data.status, 'due');
    assert.equal(fake.calls('POST', `${ISSUER}/api/v1/platform-billing/invoices`)[0].headers.Authorization, 'Bearer machine:billing');
    assert.equal((await bahari.cancelSubscription('ref/1')).data.cancel_at_period_end, true);
    assert.deepEqual((await bahari.updateSubscription('ref-2', { amount: '5.00' })).data, { amount: '5.00' });
  });

  test('cached machine tokens can be sealed', async () => {
    const cache = new MemoryCache();
    const fake = new FakeFetch({
      [DISCOVERY]: reply(discovery()),
      [`POST ${ISSUER}/oauth/token`]: reply({ access_token: 'machine', expires_in: 3600 }),
      [`GET ${ISSUER}/api/v1/ping`]: reply({ ok: true }),
    });
    const options = { cache, seal: (value) => `sealed:${Buffer.from(value).toString('base64')}`, unseal: (value) => Buffer.from(value.slice(7), 'base64').toString() };
    await client(fake, options).api('GET', 'ping');
    await client(fake, options).api('GET', 'ping');
    assert.equal(fake.calls('POST', `${ISSUER}/oauth/token`).length, 1);
    assert.ok(fake.calls('GET', `${ISSUER}/api/v1/ping`).every((request) => request.headers.Authorization === 'Bearer machine'));
  });

  test('client revoke posts both tokens; unreachable Bahari is a BahariError', async () => {
    const fake = new FakeFetch({ [DISCOVERY]: reply(discovery()), [`POST ${ISSUER}/oauth/revoke`]: reply({}) });
    await client(fake).revoke('client', { access_token: 'a', refresh_token: 'r' });
    const hints = fake.calls('POST', `${ISSUER}/oauth/revoke`).map((request) => new URLSearchParams(request.body).get('token_type_hint'));
    assert.deepEqual(hints, ['refresh_token', 'access_token']);

    const down = client(new FakeFetch({ [DISCOVERY]: reply(discovery()) }));
    await assert.rejects(down.api('GET', 'ping'), (error) => error instanceof BahariError && /could not be reached/.test(error.message));
    await assert.rejects(down.beginLogin('sideways', 'https://x'), TypeError);
    const unconfigured = new BahariClient({ issuer: ISSUER, clientId: '', clientSecret: '' }, { fetch: fake.fetch });
    await assert.rejects(unconfigured.beginLogin('client', 'https://x'), /not configured/);
  });

  test('completeLogin rejects expired transactions', async () => {
    const bahari = client(new FakeFetch({ [DISCOVERY]: reply(discovery()) }));
    const login = await bahari.beginLogin('client', 'https://app.example.test/cb');
    await assert.rejects(bahari.completeLogin({ ...login.transaction, createdAt: login.transaction.createdAt - 601 }, 'code'), /expired/);
  });
});

describe('0.4.0: role, branding and maintenance', () => {
  test('branding and maintenance are cached and fall back to the last good copy', async () => {
    const cache = new MemoryCache();
    const data = { name: 'Bahari Reseller', access_mode: 'hybrid', brand_color: '#0EA5E9', maintenance: { enabled: true, message: 'Back by 3 PM.' }, support: { email: 'help@reseller.test', phone: null, url: null } };
    const fake = new FakeFetch({ [DISCOVERY]: reply(discovery()), [`GET ${ISSUER}/api/v1/platform-branding/reseller`]: reply({ data }) });
    const bahari = client(fake, { cache });

    assert.equal((await bahari.branding()).name, 'Bahari Reseller');
    assert.deepEqual(await bahari.maintenance(), { enabled: true, message: 'Back by 3 PM.' });
    assert.equal((await bahari.branding()).support.email, 'help@reseller.test');
    assert.equal(fake.sent.length, 2, 'Branding is cached.');

    await cache.delete(`bahari:branding:${sha(`${ISSUER}|reseller`)}`);
    const offline = client(new FakeFetch({ [DISCOVERY]: reply(discovery()) }), { cache });
    assert.equal((await offline.maintenance()).enabled, true, 'The last good copy is used when Bahari cannot be reached.');
    assert.deepEqual(await client(new FakeFetch({ [DISCOVERY]: reply(discovery()) })).maintenance(), { enabled: false, message: null });
  });

  test('role reports admin rights from Bahari', () => {
    const bahari = client(new FakeFetch({}));
    const customer = { kind: 'client', subject: SUBJECT, profile: profile() };
    const wouldBeAdmin = { kind: 'client', subject: SUBJECT, profile: profile({ admin_access: { platform: 'reseller', role: 'ADMIN', two_factor_ready: true } }) };
    const otherPlatform = { kind: 'client', subject: SUBJECT, profile: profile({ admin_access: { platform: 'sms', role: 'SUPER_ADMIN', two_factor_ready: true } }) };
    const admin = { kind: 'admin', subject: ADMIN_ID, profile: adminProfile({ role: 'SUPER_ADMIN' }) };

    assert.deepEqual([customer, wouldBeAdmin, otherPlatform, admin].map((identity) => bahari.role(identity)), ['USER', 'ADMIN', 'USER', 'SUPER_ADMIN']);
    assert.deepEqual([customer, wouldBeAdmin, admin].map((identity) => bahari.isAdmin(identity)), [false, false, true]);
    assert.deepEqual([BahariClient.linkedUserId(customer), BahariClient.linkedUserId(admin)], [SUBJECT, SUBJECT]);
  });
});
