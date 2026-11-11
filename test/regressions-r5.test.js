'use strict';
// Round 5 regression tests for bugs found by the chaos suite.
const test = require('node:test');
const assert = require('node:assert');
const { createAuthenticator, AuthError, DEFAULT_AUTH_TIMEOUT_MS } = require('../src/auth');

const req = (tok = 'abc.def.ghi') => ({ headers: { authorization: `Bearer ${tok}` } });

test('R5-1: authenticate() rejects provider output that is not a claims object with a string sub', async () => {
  for (const c of [null, undefined, [], [{ sub: 'a' }], 'x', 1, true, {}, { sub: '' }, { sub: 1 }, { sub: null }, { sub: ['a'] }, { roles: ['admin'] }]) {
    const a = createAuthenticator({ verify: async () => c });
    await assert.rejects(a.authenticate(req()), (e) => e instanceof AuthError && e.code === 'invalid_token', JSON.stringify(c));
  }
  const ok = createAuthenticator({ name: 'p', verify: async () => ({ sub: 'jean', roles: ['admin'] }) });
  assert.equal((await ok.authenticate(req())).sub, 'jean');
});

test('R5-2: authenticate() times out a provider that never settles with auth_unavailable', async () => {
  const a = createAuthenticator({ verify: () => new Promise(() => {}) }, { timeoutMs: 30 });
  const t0 = Date.now();
  await assert.rejects(a.authenticate(req()), (e) => e instanceof AuthError && e.code === 'auth_unavailable');
  assert.ok(Date.now() - t0 < 1000);
});

test('R5-2: the timeout timer is cleared on success (no lingering timers) and sync throws still reject', async () => {
  const a = createAuthenticator({ verify: () => ({ sub: 's' }) }, { timeoutMs: 60000 });
  const before = process.getActiveResourcesInfo().filter((r) => r === 'Timeout').length;
  await a.authenticate(req());
  assert.equal(process.getActiveResourcesInfo().filter((r) => r === 'Timeout').length, before);
  const b = createAuthenticator({ verify: () => { throw new Error('sync'); } });
  await assert.rejects(b.authenticate(req()), /sync/);
});

test('R5-2: timeout option is validated and defaults to 5000 ms', () => {
  assert.equal(DEFAULT_AUTH_TIMEOUT_MS, 5000);
  assert.equal(createAuthenticator({ verify() {} }).timeoutMs, 5000);
  for (const bad of [0, -1, 1.5, 60001, NaN, '100', null]) {
    assert.throws(() => createAuthenticator({ verify() {} }, { timeoutMs: bad }), /Auth timeout/, String(bad));
  }
});
