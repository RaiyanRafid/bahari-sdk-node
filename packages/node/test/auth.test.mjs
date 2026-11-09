import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { describe, test } from 'node:test';
import { MemoryStore, createBahariAuth, publicProfile, safeReturnPath } from '../dist/esm/index.js';
import { ADMIN_ID, FakeFetch, ISSUER, OTHER, SUBJECT, adminProfile, client, jwt, profile, reply, silent, standardRoutes } from './helpers.mjs';

const APP = 'https://app.example.test';
const ADMIN_ACCESS = { platform: 'reseller', role: 'ADMIN', two_factor_ready: true };
const LOGOUT_EVENT = { 'http://schemas.openid.net/event/backchannel-logout': {} };

/** A tiny browser: keeps the bahari_sid cookie between calls. */
class Browser {
  constructor(auth) {
    this.auth = auth;
    this.cookie = null;
  }

  async request(method, path, { headers = {}, body } = {}) {
    const request = new Request(`${APP}${path}`, {
      method,
      headers: { ...(this.cookie ? { cookie: `bahari_sid=${this.cookie}` } : {}), ...headers },
      body,
      redirect: 'manual',
    });
    const result = await this.auth.handle(request);
    for (const line of result?.cookies ?? []) {
      const match = /^bahari_sid=([^;]*)/.exec(line);
      if (match) this.cookie = decodeURIComponent(match[1]);
    }

    return result;
  }

  get(path, options) {
    return this.request('GET', path, options);
  }

  post(path, options) {
    return this.request('POST', path, options);
  }
}

function setup({ customer = profile(), adminData = adminProfile(), options = {}, sessionStore } = {}) {
  let nonce = null;
  const routes = standardRoutes({ customer, adminData, tokenNonce: () => nonce });
  const fake = new FakeFetch(routes);
  const bahari = client(fake);
  const sessions = sessionStore ?? new MemoryStore();
  const auth = createBahariAuth({ client: bahari, sessionStore: sessions, baseUrl: APP, logger: silent, ...options });
  const browser = new Browser(auth);

  /** Follows a sign-in from {prefix}/.../login to the app's callback, as Bahari would. */
  const signIn = async (path, code = 'code') => {
    const start = await browser.get(path);
    assert.equal(start.status, 302, `login ${path}`);
    const url = new URL(start.headers.Location);
    nonce = url.searchParams.get('nonce');
    const kind = url.pathname.startsWith('/admin-sso') ? 'admin' : 'client';

    return browser.get(`/auth/${kind}/callback?state=${url.searchParams.get('state')}&code=${code}`);
  };

  return { fake, bahari, auth, browser, sessions, signIn, routes };
}

describe('Auto admin detection', () => {
  test('a customer linked to an admin continues to the admin sign-in and lands in the admin area', async () => {
    const { auth, browser, signIn, fake } = setup({ customer: profile({ admin_access: ADMIN_ACCESS }) });

    const start = await browser.get('/auth/login?return_to=%2Fdashboard%2Forders');
    assert.equal(start.status, 302);
    assert.ok(start.headers.Location.startsWith(`${ISSUER}/oauth/authorize?`));
    assert.match(start.cookies[0], /^bahari_sid=[A-Za-z0-9_-]{43}; Path=\/; Max-Age=28800; HttpOnly; Secure; SameSite=Lax$/);
    const firstCookie = browser.cookie;
    const url = new URL(start.headers.Location);
    assert.equal(url.searchParams.get('redirect_uri'), `${APP}/auth/client/callback`);

    const nonce = url.searchParams.get('nonce');
    fake.routes[`POST ${ISSUER}/oauth/token`] = reply({ access_token: 'access-1', refresh_token: 'refresh-1', expires_in: 3600, id_token: jwt({ nonce }) });
    const callback = await browser.get(`/auth/client/callback?state=${url.searchParams.get('state')}&code=c1`);
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.Location, '/auth/admin/login?return_to=%2Fadmin');
    assert.equal(callback.headers['Referrer-Policy'], 'no-referrer');
    assert.notEqual(browser.cookie, firstCookie, 'the browser session id is regenerated after sign-in');

    const adminStart = await browser.get(callback.headers.Location);
    const adminUrl = new URL(adminStart.headers.Location);
    assert.equal(adminUrl.origin + adminUrl.pathname, 'https://admin.example.test/admin-sso/authorize');
    assert.equal(adminUrl.searchParams.get('redirect_uri'), `${APP}/auth/admin/callback`);

    const adminCallback = await browser.get(`/auth/admin/callback?state=${adminUrl.searchParams.get('state')}&code=c2`);
    assert.equal(adminCallback.status, 302);
    assert.equal(adminCallback.headers.Location, '/admin');

    const adminSession = await browser.get('/auth/session?kind=admin');
    assert.equal(adminSession.status, 200);
    assert.deepEqual(JSON.parse(adminSession.body).kind, 'admin');
    assert.equal(JSON.parse(adminSession.body).profile.id, ADMIN_ID);
    const clientSession = JSON.parse((await browser.get('/auth/session')).body);
    assert.equal(clientSession.kind, 'client');
    assert.deepEqual(clientSession.profile.admin_access, ADMIN_ACCESS);

    // The expected admin user is consumed: a later manual admin sign-in carries no expectation.
    const outcome = await auth.authenticate(new Request(`${APP}/admin/users`, { headers: { cookie: `bahari_sid=${browser.cookie}` } }));
    assert.equal(outcome.ok, true);
    assert.equal(outcome.kind, 'admin');
  });

  test('an admin whose user_id is not the signed-in customer gets no admin session', async () => {
    const { browser, signIn, fake } = setup({ customer: profile({ admin_access: ADMIN_ACCESS }), adminData: adminProfile({ user_id: OTHER }) });

    const callback = await signIn('/auth/login');
    assert.equal(callback.headers.Location, '/auth/admin/login?return_to=%2Fadmin');
    const adminCallback = await signIn(callback.headers.Location, 'c2');
    assert.equal(adminCallback.status, 302);
    assert.equal(adminCallback.headers.Location, '/dashboard');

    assert.equal((await browser.get('/auth/session?kind=admin')).status, 401);
    assert.equal((await browser.get('/auth/session?kind=client')).status, 200);
    assert.equal(fake.calls('POST', `${ISSUER}/api/v1/admin-sso/revoke`).length, 1, 'the unlinked admin session is revoked at Bahari');
  });

  test('a missing user_id also fails closed', async () => {
    const { browser, signIn } = setup({ customer: profile({ admin_access: ADMIN_ACCESS }), adminData: adminProfile({ user_id: null }) });
    const callback = await signIn('/auth/login');
    assert.equal((await signIn(callback.headers.Location)).headers.Location, '/dashboard');
    assert.equal((await browser.get('/auth/session?kind=admin')).status, 401);
  });

  test('customers without admin access, explicit client sign-ins and autoAdmin=false stay in the client area', async () => {
    const plain = setup({ customer: profile({ admin_access: null }) });
    assert.equal((await plain.signIn('/auth/login?return_to=/dashboard/billing')).headers.Location, '/dashboard/billing');

    const explicit = setup({ customer: profile({ admin_access: ADMIN_ACCESS }) });
    assert.equal((await explicit.signIn('/auth/client/login')).headers.Location, '/dashboard');

    const disabled = setup({ customer: profile({ admin_access: ADMIN_ACCESS }), options: { autoAdmin: false } });
    assert.equal((await disabled.signIn('/auth/login')).headers.Location, '/dashboard');

    const otherPlatform = setup({ customer: profile({ admin_access: { ...ADMIN_ACCESS, platform: 'sms' } }) });
    assert.equal((await otherPlatform.signIn('/auth/login')).headers.Location, '/dashboard');
  });

  test('a normal admin sign-in (no auto) does not require a linked customer', async () => {
    const { browser, signIn } = setup({ adminData: adminProfile({ user_id: null }) });
    const callback = await signIn('/auth/admin/login?return_to=/admin/settings');
    assert.equal(callback.headers.Location, '/admin/settings');
    assert.equal((await browser.get('/auth/session?kind=admin')).status, 200);
  });
});

describe('Sign-in, session JSON and logout', () => {
  test('the session JSON never contains tokens', async () => {
    const customer = profile({ admin_access: null, nested: { api_token: 'leak-1', keep: 'yes' }, client_secret: 'leak-2' });
    const { browser, signIn } = setup({ customer });
    await signIn('/auth/client/login');
    const response = await browser.get('/auth/session');
    assert.equal(response.status, 200);
    assert.equal(response.headers['Cache-Control'], 'no-store');
    const body = JSON.parse(response.body);
    assert.deepEqual(Object.keys(body).sort(), ['kind', 'profile']);
    for (const secret of ['access-1', 'refresh-1', 'leak-1', 'leak-2', 'session_token', 'id_token', 'eyJ']) {
      assert.equal(response.body.includes(secret), false, `session JSON contains ${secret}`);
    }
    assert.equal(body.profile.nested.keep, 'yes');
    assert.deepEqual(publicProfile({ session_token: 'x', tokens: { a: 1 }, a: [{ refresh_token: 'y', b: 2 }] }), { a: [{ b: 2 }] });

    const admin = setup();
    await admin.signIn('/auth/admin/login');
    const adminBody = (await admin.browser.get('/auth/session?kind=admin')).body;
    assert.equal(adminBody.includes('s'.repeat(64)), false);
  });

  test('unauthenticated session JSON is 401; unknown kinds are 404', async () => {
    const { browser } = setup();
    assert.equal((await browser.get('/auth/session')).status, 401);
    assert.equal((await browser.get('/auth/session?kind=root')).status, 404);
    assert.equal((await browser.get('/auth/root/login')), null);
    assert.equal((await browser.get('/auth/unknown')), null);
    assert.equal((await browser.get('/elsewhere')), null);
    assert.equal((await browser.post('/auth/client/login')).status, 405);
  });

  test('state must match a pending sign-in of this browser, of this kind, within 10 minutes', async () => {
    const { browser, auth, bahari } = setup();
    assert.equal((await browser.get('/auth/client/callback?state=abc&code=x')).status, 422);
    const start = await browser.get('/auth/client/login');
    const state = new URL(start.headers.Location).searchParams.get('state');

    const stranger = new Browser(auth);
    assert.equal((await stranger.get(`/auth/client/callback?state=${state}&code=x`)).status, 422, 'another browser cannot use the state');
    assert.equal((await browser.get(`/auth/admin/callback?state=${state}&code=x`)).status, 422, 'kind must match');
    assert.equal((await browser.get(`/auth/client/callback?state=${state}&code=x`)).status, 422, 'the state is single-use');

    const denied = await browser.get('/auth/client/login');
    const deniedState = new URL(denied.headers.Location).searchParams.get('state');
    const response = await browser.get(`/auth/client/callback?state=${deniedState}&error=access_denied`);
    assert.equal(response.status, 422);
    assert.match(response.body, /not approved/);

    const late = await browser.get('/auth/client/login');
    const lateState = new URL(late.headers.Location).searchParams.get('state');
    const realNow = bahari.now.bind(bahari);
    bahari.now = () => realNow() + 601;
    assert.match((await browser.get(`/auth/client/callback?state=${lateState}&code=x`)).body, /expired/);
  });

  test('a failed exchange answers 503 and creates no session', async () => {
    const { browser, signIn, fake } = setup();
    fake.routes[`GET ${ISSUER}/oauth/user`] = reply({ data: profile({ status: 'suspended' }) });
    const response = await signIn('/auth/client/login');
    assert.equal(response.status, 503);
    assert.equal((await browser.get('/auth/session')).status, 401);
  });

  test('sign-in is unavailable until the client credentials are set', async () => {
    const { auth } = setup();
    const unconfigured = createBahariAuth({ client: client(new FakeFetch(), { config: { clientId: '', clientSecret: '' } }), logger: silent, baseUrl: APP });
    assert.equal((await new Browser(unconfigured).get('/auth/client/login')).status, 503);
    assert.ok(auth);
  });

  test('create account opens Bahari registration', async () => {
    const { browser } = setup();
    const response = await browser.get('/auth/register?return_to=/dashboard/settings');
    assert.equal(response.status, 302);
    const location = new URL(response.headers.Location);
    assert.equal(location.pathname, '/oauth/authorize');
    assert.equal(location.searchParams.get('prompt'), 'create');
  });

  test('logout revokes locally and at Bahari, then redirects to Bahari logout (303)', async () => {
    const { browser, signIn, fake, sessions } = setup();
    await signIn('/auth/client/login');
    const response = await browser.post('/auth/client/logout', { headers: { origin: APP } });
    assert.equal(response.status, 303);
    const location = new URL(response.headers.Location);
    assert.equal(`${location.origin}${location.pathname}`, `${ISSUER}/oauth/logout`);
    assert.equal(location.searchParams.get('client_id'), 'client-1');
    assert.equal(location.searchParams.get('post_logout_redirect_uri'), 'https://app.example.test/');
    // The ID token lets Bahari sign out at once and return to the app (no confirmation page).
    assert.equal(location.searchParams.get('id_token_hint').split('.').length, 3);
    assert.equal(fake.calls('POST', `${ISSUER}/oauth/revoke`).length, 2);
    assert.equal((await browser.get('/auth/session')).status, 401);
    assert.equal(sessions.size, 1);

    const admin = setup();
    await admin.signIn('/auth/admin/login');
    const adminLogout = await admin.browser.post('/auth/admin/logout');
    assert.equal(adminLogout.headers.Location, 'https://admin.example.test/admin');
    assert.equal(admin.fake.calls('POST', `${ISSUER}/api/v1/admin-sso/revoke`).length, 1);
  });

  test('cross-site logout posts are refused', async () => {
    const { browser, signIn } = setup();
    await signIn('/auth/client/login');
    assert.equal((await browser.post('/auth/client/logout', { headers: { origin: 'https://evil.example.test' } })).status, 403);
    assert.equal((await browser.post('/auth/client/logout', { headers: { 'sec-fetch-site': 'cross-site' } })).status, 403);
    assert.equal((await browser.get('/auth/session')).status, 200);
  });
});

describe('Back-channel logout', () => {
  test('ends every customer session of the subject once per jti', async () => {
    const store = new MemoryStore();
    const revoked = [];
    const original = store.revokeSubject.bind(store);
    store.revokeSubject = async (kind, subject) => {
      revoked.push([kind, subject]);
      await original(kind, subject);
    };
    const { browser, signIn, auth } = setup({ sessionStore: store });
    await signIn('/auth/client/login');
    const second = new Browser(auth);
    second.cookie = null;
    assert.equal((await browser.get('/auth/session')).status, 200);

    const token = jwt({ jti: 'logout-1', events: LOGOUT_EVENT });
    const post = (body, headers = { 'content-type': 'application/x-www-form-urlencoded' }) => second.post('/auth/backchannel-logout', { headers, body });
    const first = await post(new URLSearchParams({ logout_token: token }).toString());
    assert.equal(first.status, 200);
    assert.deepEqual(JSON.parse(first.body), { received: true });
    assert.equal(first.headers['Cache-Control'], 'no-store');
    assert.equal((await browser.get('/auth/session')).status, 401);

    const replay = await post(JSON.stringify({ logout_token: token }), { 'content-type': 'application/json' });
    assert.equal(replay.status, 200);
    assert.deepEqual(revoked, [['client', SUBJECT]], 'a repeated jti is ignored');

    await post(new URLSearchParams({ logout_token: jwt({ jti: 'logout-2', events: LOGOUT_EVENT }) }).toString());
    assert.equal(revoked.length, 2);
  });

  test('invalid, missing and oversized logout tokens are rejected', async () => {
    const { browser } = setup();
    const form = { 'content-type': 'application/x-www-form-urlencoded' };
    assert.equal((await browser.post('/auth/backchannel-logout', { headers: form, body: 'logout_token=' })).status, 422);
    assert.equal((await browser.post('/auth/backchannel-logout', { headers: form, body: `logout_token=${jwt({ jti: 'x' })}` })).status, 422);
    assert.equal((await browser.post('/auth/backchannel-logout', { headers: form, body: `logout_token=${'a'.repeat(70000)}` })).status, 413);
    assert.equal((await browser.get('/auth/backchannel-logout')).status, 405);
  });
});

describe('requireBahari: recheck on every request, fail closed', () => {
  test('rotates expiring tokens and stores them', async () => {
    const { auth, browser, signIn, fake, sessions, bahari } = setup();
    await signIn('/auth/client/login');
    const request = () => new Request(`${APP}/dashboard/orders?page=2`, { headers: { cookie: `bahari_sid=${browser.cookie}` } });
    const outcome = await auth.authenticate(request());
    assert.equal(outcome.ok, true);
    assert.equal(outcome.kind, 'client');
    assert.equal(fake.calls('POST', `${ISSUER}/oauth/token`).length, 1, 'fresh access token: no rotation');

    const realNow = bahari.now.bind(bahari);
    bahari.now = () => realNow() + 890;
    fake.routes[`POST ${ISSUER}/oauth/token`] = reply({ access_token: 'access-2', refresh_token: 'refresh-2', expires_in: 900, id_token: jwt() });
    const rotated = await auth.authenticate(request());
    assert.equal(rotated.ok, true);
    assert.equal(rotated.session.tokens.refresh_token, 'refresh-2');
    assert.equal((await sessions.find(rotated.session.id, 'client')).tokens.access_token, 'access-2');
  });

  test('a session Bahari ended is revoked locally and the browser is sent to sign in', async () => {
    const { auth, browser, signIn, fake, sessions } = setup();
    await signIn('/auth/client/login');
    const cookie = { cookie: `bahari_sid=${browser.cookie}` };
    const id = (await auth.authenticate(new Request(`${APP}/dashboard`, { headers: cookie }))).session.id;

    fake.routes[`GET ${ISSUER}/oauth/user`] = reply({ message: 'Unauthenticated.' }, 401);
    const outcome = await auth.authenticate(new Request(`${APP}/dashboard/orders?page=2`, { headers: cookie }));
    assert.equal(outcome.ok, false);
    assert.equal(outcome.response.status, 302);
    assert.equal(outcome.response.headers.Location, '/auth/client/login?return_to=%2Fdashboard%2Forders%3Fpage%3D2');
    assert.equal(await sessions.find(id, 'client'), null);

    // Even when Bahari recovers, the ended session stays ended.
    fake.routes[`GET ${ISSUER}/oauth/user`] = reply({ data: profile() });
    const json = await auth.authenticate(new Request(`${APP}/dashboard`, { headers: { ...cookie, accept: 'application/json' } }));
    assert.equal(json.ok, false);
    assert.equal(json.response.status, 401);
  });

  test('Bahari being unreachable or answering 500 also fails closed', async () => {
    for (const failure of ['network', 500]) {
      const { auth, browser, signIn, fake } = setup();
      await signIn('/auth/client/login');
      if (failure === 'network') {
        delete fake.routes[`GET ${ISSUER}/oauth/user`];
      } else {
        fake.routes[`GET ${ISSUER}/oauth/user`] = reply({ message: 'oops' }, 500);
      }
      const outcome = await auth.authenticate(new Request(`${APP}/dashboard`, { headers: { cookie: `bahari_sid=${browser.cookie}` } }));
      assert.equal(outcome.ok, false, `failure ${failure}`);
    }
  });

  test('admin role removal ends the admin session; kinds are separate', async () => {
    let data = adminProfile();
    const { auth, browser, signIn } = setup({ adminData: () => data });
    await signIn('/auth/admin/login');
    const request = (path) => new Request(`${APP}${path}`, { headers: { cookie: `bahari_sid=${browser.cookie}` } });
    assert.equal((await auth.authenticate(request('/admin'))).ok, true);
    assert.equal((await auth.authenticate(request('/dashboard'))).ok, false, 'an admin session is not a customer session');
    data = adminProfile({ role: 'SUPPORT' });
    const outcome = await auth.authenticate(request('/admin/users'));
    assert.equal(outcome.ok, false);
    assert.equal(outcome.response.headers.Location, '/auth/admin/login?return_to=%2Fadmin%2Fusers');
  });

  test('works as Express/Connect middleware on a real HTTP server', async () => {
    const { auth, browser, signIn, fake } = setup({ options: { baseUrl: null } });
    await signIn('/auth/client/login');
    const guard = auth.requireBahari();
    const server = createServer((req, res) => {
      auth.handler(req, res, () => {
        guard(req, res, (error) => {
          if (error) {
            res.statusCode = 500;
            res.end(String(error));
            return;
          }
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({ subject: req.bahari.subject, kind: req.bahari.kind }));
        });
      });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    try {
      const ok = await fetch(`${base}/dashboard`, { headers: { cookie: `bahari_sid=${browser.cookie}` }, redirect: 'manual' });
      assert.equal(ok.status, 200);
      assert.deepEqual(await ok.json(), { subject: SUBJECT, kind: 'client' });

      const anonymous = await fetch(`${base}/dashboard/x`, { redirect: 'manual' });
      assert.equal(anonymous.status, 302);
      assert.equal(anonymous.headers.get('location'), '/auth/client/login?return_to=%2Fdashboard%2Fx');

      const login = await fetch(`${base}/auth/login`, { redirect: 'manual' });
      assert.equal(login.status, 302);
      assert.match(login.headers.get('set-cookie'), /HttpOnly; Secure; SameSite=Lax/);
      assert.equal(new URL(login.headers.get('location')).searchParams.get('redirect_uri'), `${base}/auth/client/callback`);

      const session = await fetch(`${base}/auth/session`, { headers: { cookie: `bahari_sid=${browser.cookie}` } });
      assert.equal((await session.json()).profile.id, SUBJECT);

      const logout = await fetch(`${base}/auth/backchannel-logout`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ logout_token: jwt({ jti: 'srv-1', events: LOGOUT_EVENT }) }),
      });
      assert.equal(logout.status, 200);
      const after = await fetch(`${base}/dashboard`, { headers: { cookie: `bahari_sid=${browser.cookie}`, accept: 'application/json' }, redirect: 'manual' });
      assert.equal(after.status, 401);
      assert.ok(fake.sent.length > 0);
    } finally {
      server.close();
    }
  });
});

describe('Navigation routes', () => {
  test('GET returns the switcher with the wallet link; PUT validates and passes 422 through', async () => {
    const { browser, signIn, fake } = setup();
    fake.routes[`GET ${ISSUER}/api/v1/platform-navigation`] = reply({ data: { platforms: [], wallet: { url: 'x' } } });
    let status = 200;
    fake.routes[`PUT ${ISSUER}/api/v1/platform-navigation`] = () => reply(status === 200 ? { data: { pinned_keys: ['sms'] } } : { message: 'The pinned keys are invalid.' }, status);
    assert.equal((await browser.get('/auth/navigation')).status, 401);
    await signIn('/auth/client/login');

    const navigation = await browser.get('/auth/navigation');
    assert.equal(navigation.status, 200);
    assert.equal(JSON.parse(navigation.body).data.wallet.url, `${ISSUER}/dashboard/wallet?platform=reseller&return_to=%2Fdashboard`);

    const put = (body, headers = { 'content-type': 'application/json' }) => browser.request('PUT', '/auth/navigation', { headers, body });
    assert.equal((await put(JSON.stringify({ pinned_keys: ['sms'] }))).status, 200);
    status = 422;
    const invalid = await put(JSON.stringify({ pinned_keys: ['nope'] }));
    assert.equal(invalid.status, 422);
    assert.equal(JSON.parse(invalid.body).message, 'The pinned keys are invalid.');
    assert.equal((await put(JSON.stringify({ pinned_keys: 'sms' }))).status, 422);
    assert.equal((await put('pinned_keys=sms', { 'content-type': 'application/x-www-form-urlencoded' })).status, 415);
    assert.equal((await put(JSON.stringify({ pinned_keys: [] }), { 'content-type': 'application/json', origin: 'https://evil.example.test' })).status, 403);
  });
});

describe('Return-path sanitising (BahariManager::safeReturnPath)', () => {
  const cases = [
    [null, '/dashboard'],
    [undefined, '/dashboard'],
    ['', '/dashboard'],
    [42, '/dashboard'],
    ['/dashboard', '/dashboard'],
    ['/dashboard/orders?page=2', '/dashboard/orders?page=2'],
    ['/dashboard?tab=x', '/dashboard?tab=x'],
    ['/dashboardx', '/dashboard'],
    ['/admin', '/dashboard'],
    ['https://evil.example.test/dashboard', '/dashboard'],
    ['//evil.example.test', '/dashboard'],
    ['/dashboard/../admin', '/dashboard'],
    ['/dashboard/%2e%2e/admin', '/dashboard'],
    ['/dashboard/%2E%2E%2Fadmin', '/dashboard'],
    ['/dashboard\\evil', '/dashboard'],
    ['/dashboard/%5Cevil', '/dashboard'],
    ['/dashboard/a b', '/dashboard'],
    ['/dashboard/%20', '/dashboard'],
    ['/dashboard/%0d%0aSet-Cookie:x', '/dashboard'],
    ['/dashboard/%7f', '/dashboard'],
    ['/dashboard/\u0000', '/dashboard'],
    [`/dashboard/${'a'.repeat(2050)}`, '/dashboard'],
    ['/dashboard/%zz', '/dashboard/%zz'],
  ];
  for (const [value, expected] of cases) {
    test(`${JSON.stringify(value)?.slice(0, 40)} -> ${expected}`, () => {
      assert.equal(safeReturnPath('/dashboard/', value), expected);
    });
  }

  test('a root area accepts any local path and nothing external', () => {
    assert.equal(safeReturnPath('/', '/anything?x=1'), '/anything?x=1');
    assert.equal(safeReturnPath('/', '//evil.example.test'), '/');
    assert.equal(safeReturnPath('/', 'https://evil.example.test'), '/');
  });

  test('login uses the sanitised return path', async () => {
    const { browser, signIn } = setup();
    assert.equal((await signIn('/auth/client/login?return_to=https%3A%2F%2Fevil.example.test')).headers.Location, '/dashboard');
    assert.equal((await signIn('/auth/admin/login?return_to=%2Fdashboard')).headers.Location, '/admin');
    assert.ok(browser.cookie);
  });
});
