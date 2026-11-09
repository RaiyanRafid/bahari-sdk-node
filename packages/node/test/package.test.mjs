import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { test } from 'node:test';

const require = createRequire(import.meta.url);

test('the package resolves for both import and require, with the same API', async () => {
  const esm = await import('@bahari/node');
  const cjs = require('@bahari/node');
  for (const name of ['BahariClient', 'Discovery', 'BahariError', 'HttpError', 'InvalidTokenError', 'AccessDeniedError', 'createBahariAuth', 'MemoryStore', 'MemoryCache', 'Config']) {
    assert.equal(typeof esm[name], 'function', `esm ${name}`);
    assert.equal(typeof cjs[name], 'function', `cjs ${name}`);
  }
  assert.equal(esm.SDK, '@bahari/node/0.3.0');
  assert.equal(cjs.VERSION, require('../package.json').version);
});

test('the edge-safe return-path entry has no Node built-ins', async () => {
  const { safeReturnPath } = await import('@bahari/node/return-path');
  assert.equal(safeReturnPath('/admin', '/admin/users'), '/admin/users');
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../dist/esm/return-path.js', import.meta.url), 'utf8');
  assert.equal(/from ['"]node:|require\(/.test(source), false);
});
