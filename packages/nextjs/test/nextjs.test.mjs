import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { BahariAuth, createBahari, createBahariRouteHandlers, getBahariSession } from '@bahari/nextjs';
import { bahariMiddleware, createBahariMiddleware } from '@bahari/nextjs/middleware';
import { MemoryStore } from '@bahari/node';
import { FakeFetch, ISSUER, SUBJECT, client, jwt, profile, reply, silent, standardRoutes } from '../../node/test/helpers.mjs';

const APP = 'https://app.example.test';

function setup(customer = profile()) {
  let nonce = null;
  const fake = new FakeFetch(standardRoutes({ customer, tokenNonce: () => nonce }));
  const bahari = createBahari({ client: client(fake, { sdk: '@bahari/nextjs/0.1.0' }), baseUrl: APP, logger: silent, sessionStore: new MemoryStore() });
  const { GET, POST, PUT } = bahari.handlers;
  let cookie = null;
  const call = async (handler, method, path, init = {}) => {
    const response = await handler(new Request(`${APP}${path}`, { method, ...init, headers: { ...(cookie ? { cookie: `bahari_sid=${cookie}` } : {}), ...(init.headers ?? {}) } }));
    const set = response.headers.get('set-cookie');
    const match = set && /bahari_sid=([^;]*)/.exec(set);
    if (match) cookie = match[1];

    return response;
  };
  const signIn = async () => {
    const start = await call(GET, 'GET', '/auth/client/login');
    const url = new URL(start.headers.get('location'));
    nonce = url.searchParams.get('nonce');

    return call(GET, 'GET', `/auth/client/callback?state=${url.searchParams.get('state')}&code=c1`);
  };
  const cookies = () => ({ get: (name) => (name === 'bahari_sid' && cookie ? { value: cookie } : undefined) });

  return { fake, bahari, GET, POST, PUT, call, signIn, cookies, cookie: () => cookie };
}

describe('Route handlers (app/auth/[...bahari]/route.ts)', () => {
  test('GET/POST/PUT handle the Bahari routes with Web Request/Response', async () => {
    const { GET, POST, PUT, call, signIn, fake } = setup();
    const callback = await signIn();
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get('location'), '/dashboard');
    assert.match(callback.headers.get('set-cookie'), /HttpOnly; Secure; SameSite=Lax/);
    assert.equal(fake.sent[0].headers['X-Bahari-SDK'], '@bahari/nextjs/0.1.0');

    const session = await call(GET, 'GET', '/auth/session');
    assert.equal(session.status, 200);
    const body = await session.text();
    assert.equal(JSON.parse(body).profile.id, SUBJECT);
    assert.equal(body.includes('access-1') || body.includes('refresh-1'), false);

    fake.routes[`PUT ${ISSUER}/api/v1/platform-navigation`] = reply({ data: { pinned_keys: [] } });
    const put = await call(PUT, 'PUT', '/auth/navigation', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pinned_keys: [] }) });
    assert.equal(put.status, 200);

    const logout = await call(POST, 'POST', '/auth/client/logout');
    assert.equal(logout.status, 303);
    assert.equal((await call(GET, 'GET', '/auth/session')).status, 401);
    assert.equal((await call(GET, 'GET', '/auth/nothing-here')).status, 404);
  });

  test('back-channel logout through the POST handler', async () => {
    const { POST, call, signIn, GET } = setup();
    await signIn();
    const response = await call(POST, 'POST', '/auth/backchannel-logout', {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ logout_token: jwt({ jti: 'next-1', events: { 'http://schemas.openid.net/event/backchannel-logout': {} } }) }).toString(),
    });
    assert.equal(response.status, 200);
    assert.equal((await call(GET, 'GET', '/auth/session')).status, 401);
  });

  test('createBahariRouteHandlers accepts the bahari object, a BahariAuth or options', async () => {
    const { bahari } = setup();
    assert.equal(typeof createBahariRouteHandlers(bahari).GET, 'function');
    assert.equal(typeof createBahariRouteHandlers(bahari.auth).PUT, 'function');
    const fromOptions = createBahariRouteHandlers({ config: { issuer: ISSUER, clientId: '', clientSecret: '' }, logger: silent });
    const response = await fromOptions.GET(new Request(`${APP}/auth/client/login`));
    assert.equal(response.status, 503, 'unconfigured credentials');
    assert.ok(bahari.auth instanceof BahariAuth);
  });
});

describe('getBahariSession (server components)', () => {
  test('reads the cookie through a cookies getter, rechecks with Bahari and returns no tokens', async () => {
    const { bahari, signIn, cookies, fake } = setup();
    assert.equal(await bahari.getSession({ cookies }), null);
    await signIn();

    const session = await getBahariSession(bahari, { cookies });
    assert.equal(session.kind, 'client');
    assert.equal(session.subject, SUBJECT);
    assert.deepEqual(Object.keys(session).sort(), ['kind', 'profile', 'subject']);
    assert.equal(JSON.stringify(session).includes('access-1'), false);
    // async cookies() (Next 15+) and a plain store also work
    assert.equal((await bahari.getSession({ cookies: async () => cookies() })).subject, SUBJECT);
    assert.equal((await bahari.getSession({ cookies: cookies() })).subject, SUBJECT);
    assert.equal(await bahari.getSession({ cookies, kind: 'admin' }), null);

    fake.routes[`GET ${ISSUER}/oauth/user`] = reply({ data: profile({ status: 'suspended' }) });
    assert.equal(await bahari.getSession({ cookies }), null, 'fails closed');
    fake.routes[`GET ${ISSUER}/oauth/user`] = reply({ data: profile() });
    assert.equal(await bahari.getSession({ cookies }), null, 'stays ended');
  });

  test('requireSession redirects to the sign-in when signed out', async () => {
    const { bahari, cookies } = setup();
    const redirect = (url) => {
      throw Object.assign(new Error('NEXT_REDIRECT'), { url });
    };
    await assert.rejects(bahari.requireSession({ cookies, redirect, returnTo: '/dashboard/orders' }), (error) => error.url === '/auth/client/login?return_to=%2Fdashboard%2Forders');
    await assert.rejects(bahari.requireSession({ cookies, redirect, kind: 'admin', returnTo: 'https://evil.example.test' }), (error) => error.url === '/auth/admin/login?return_to=%2Fadmin');
  });
});

describe('bahariMiddleware (edge gate)', () => {
  test('redirects protected paths without a session cookie to the sign-in of their kind', () => {
    const redirect = bahariMiddleware(new Request(`${APP}/dashboard/orders?page=2`));
    assert.equal(redirect.status, 307);
    assert.equal(redirect.headers.get('location'), `${APP}/auth/client/login?return_to=%2Fdashboard%2Forders%3Fpage%3D2`);
    assert.equal(bahariMiddleware(new Request(`${APP}/admin`)).headers.get('location'), `${APP}/auth/admin/login?return_to=%2Fadmin`);
    assert.equal(bahariMiddleware(new Request(`${APP}/admin/x`, { headers: { accept: 'application/json' } })).status, 401);
  });

  test('lets public paths, auth routes and requests with a session cookie through', () => {
    const sid = 'a'.repeat(43);
    assert.equal(bahariMiddleware(new Request(`${APP}/`)), undefined);
    assert.equal(bahariMiddleware(new Request(`${APP}/dashboardx`)), undefined);
    assert.equal(bahariMiddleware(new Request(`${APP}/auth/login`)), undefined);
    assert.equal(bahariMiddleware(new Request(`${APP}/dashboard`, { headers: { cookie: `x=1; bahari_sid=${sid}` } })), undefined);
    assert.equal(bahariMiddleware(new Request(`${APP}/dashboard`, { headers: { cookie: 'bahari_sid=short' } })).status, 307);
  });

  test('custom prefix, areas and cookie name', () => {
    const gate = createBahariMiddleware({ prefix: '/sso', kinds: { client: { path: '/app' } }, cookieName: 'sid' });
    assert.equal(gate(new Request(`${APP}/app/x`)).headers.get('location'), `${APP}/sso/client/login?return_to=%2Fapp%2Fx`);
    assert.equal(gate(new Request(`${APP}/admin`)), undefined);
  });

  test('the middleware entry imports no Node built-ins', async () => {
    const { readFileSync } = await import('node:fs');
    const source = readFileSync(new URL('../dist/middleware.js', import.meta.url), 'utf8');
    assert.equal(/from ['"]node:/.test(source), false);
    assert.match(source, /@bahari\/node\/return-path/);
  });
});
