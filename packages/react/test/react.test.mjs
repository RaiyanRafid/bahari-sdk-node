import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { describe, test } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import {
  BahariProvider,
  SignInButton,
  CreateAccountButton,
  registerHref,
  SignOutButton,
  fetchNavigation,
  fetchSession,
  loginHref,
  logoutAction,
  savePinned,
  useBahariNavigation,
  useBahariSession,
} from '@bahari/react';

const SESSION = { kind: 'client', profile: { id: '0198a6c1-1111-7000-8000-000000000001', name: 'Rafi', email: 'rafi@example.test', admin_access: null } };

function fakeFetch(routes) {
  const sent = [];
  const fetch = async (url, init = {}) => {
    sent.push({ url, ...init });
    const route = routes[`${init.method ?? 'GET'} ${url}`];
    if (!route) throw new TypeError(`unexpected ${init.method} ${url}`);
    const [status, body] = typeof route === 'function' ? route(init) : route;

    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  };

  return { fetch, sent };
}

describe('URL helpers', () => {
  test('sign-in links and the sign-out action', () => {
    assert.equal(loginHref(), '/auth/login');
    assert.equal(loginHref('/auth/', 'admin'), '/auth/admin/login');
    assert.equal(loginHref('sso', 'client', '/dashboard/orders?x=1'), '/sso/client/login?return_to=%2Fdashboard%2Forders%3Fx%3D1');
    assert.equal(logoutAction(undefined, 'client'), '/auth/client/logout');
  });
});

describe('Backend calls (no tokens, same-origin only)', () => {
  test('fetchSession returns the session, null when signed out, and strips any secret-looking keys', async () => {
    const { fetch, sent } = fakeFetch({ 'GET /auth/session': [200, { ...SESSION, profile: { ...SESSION.profile, access_token: 'x', nested: { session_token: 'y' } } }], 'GET /auth/session?kind=admin': [401, { message: 'no' }] });
    const session = await fetchSession({ fetch });
    assert.equal(session.profile.name, 'Rafi');
    assert.equal('access_token' in session.profile, false);
    assert.deepEqual(session.profile.nested, {});
    assert.equal(sent[0].credentials, 'same-origin');
    assert.equal(sent[0].headers.Accept, 'application/json');
    assert.equal(await fetchSession({ fetch, kind: 'admin' }), null);
  });

  test('fetchSession rejects errors and malformed answers', async () => {
    const { fetch } = fakeFetch({ 'GET /auth/session': [500, {}], 'GET /auth/session?kind=client': [200, { kind: 'root', profile: {} }] });
    await assert.rejects(fetchSession({ fetch }), /500/);
    await assert.rejects(fetchSession({ fetch, kind: 'client' }), /invalid/);
  });

  test('navigation and pinned platforms', async () => {
    let status = 200;
    const { fetch, sent } = fakeFetch({
      'GET /auth/navigation?kind=client': [200, { data: { platforms: [{ key: 'reseller' }] } }],
      'GET /auth/navigation': [401, {}],
      'PUT /auth/navigation': () => [status, status === 200 ? { data: { pinned_keys: ['sms'] } } : { message: 'invalid' }],
    });
    assert.deepEqual(await fetchNavigation({ fetch, kind: 'client' }), { platforms: [{ key: 'reseller' }] });
    assert.equal(await fetchNavigation({ fetch }), null);
    assert.deepEqual(await savePinned(['sms'], { fetch }), { ok: true, status: 200, data: { data: { pinned_keys: ['sms'] } } });
    assert.equal(sent.at(-1).headers['Content-Type'], 'application/json');
    assert.deepEqual(JSON.parse(sent.at(-1).body), { pinned_keys: ['sms'] });
    status = 422;
    const invalid = await savePinned(['nope'], { fetch });
    assert.equal(invalid.ok, false);
    assert.equal(invalid.status, 422);
  });
});

describe('Components (server-rendered)', () => {
  test('CreateAccountButton links to Bahari registration', () => {
    assert.equal(renderToStaticMarkup(createElement(CreateAccountButton)), '<a href="/auth/register">Create a Bahari account</a>');
    assert.equal(registerHref('/auth', '/dashboard'), '/auth/register?return_to=%2Fdashboard');
  });

  test('SignInButton links to the automatic or kind sign-in', () => {
    assert.equal(renderToStaticMarkup(createElement(SignInButton)), '<a href="/auth/login">Sign in with Bahari</a>');
    assert.equal(
      renderToStaticMarkup(createElement(SignInButton, { kind: 'admin', returnTo: '/admin/users', className: 'btn' }, 'Admin')),
      '<a class="btn" href="/auth/admin/login?return_to=%2Fadmin%2Fusers">Admin</a>',
    );
  });

  test('SignOutButton is a POST form', () => {
    assert.equal(
      renderToStaticMarkup(createElement(SignOutButton, { kind: 'client', className: 'link' })),
      '<form action="/auth/client/logout" method="post"><button class="link" type="submit">Sign out</button></form>',
    );
  });

  test('BahariProvider shares the session and its prefix', () => {
    function Name() {
      const { session, status } = useBahariSession();

      return createElement('span', null, `${status}:${session?.profile.name ?? '-'}`);
    }
    const html = renderToStaticMarkup(
      createElement(BahariProvider, { prefix: '/sso', initialSession: SESSION }, createElement(Name), createElement(SignInButton, { kind: 'client' })),
    );
    assert.equal(html, '<span>authenticated:Rafi</span><a href="/sso/client/login">Sign in with Bahari</a>');
    assert.equal(renderToStaticMarkup(createElement(BahariProvider, { initialSession: null }, createElement(Name))), '<span>unauthenticated:-</span>');
    assert.equal(renderToStaticMarkup(createElement(BahariProvider, {}, createElement(Name))), '<span>loading:-</span>');
  });

  test('useBahariSession requires the provider; useBahariNavigation starts loading', () => {
    function Bare() {
      useBahariSession();

      return null;
    }
    assert.throws(() => renderToStaticMarkup(createElement(Bare)), /BahariProvider/);
    function Nav() {
      return createElement('i', null, useBahariNavigation().status);
    }
    assert.equal(renderToStaticMarkup(createElement(Nav)), '<i>loading</i>');
  });
});

describe('Browser bundle hygiene', () => {
  test('the package has no secrets, no Node built-ins and marks itself as a client module', () => {
    const dist = new URL('../dist/', import.meta.url);
    for (const file of readdirSync(dist).filter((name) => name.endsWith('.js'))) {
      const source = readFileSync(new URL(file, dist), 'utf8');
      assert.equal(/client_secret|clientSecret|from ['"]node:|process\.env/.test(source), false, file);
    }
    assert.match(readFileSync(new URL('index.js', dist), 'utf8'), /^'use client';/);
  });
});
