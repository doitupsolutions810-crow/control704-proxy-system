'use strict';
// Auth-provider timeout / 503 path under load, provider races and retries, late settlement.
const test = require('node:test');
const assert = require('node:assert');
const { createAvroneProvider } = require('../src/auth/avroneProvider');
const { sign, claims, config, startServer, raw, bearer } = require('./helpers');

const real = createAvroneProvider(config);
const tech = sign(claims({ sub: 'tech1', roles: ['technician'] }));
const hungTok = sign(claims({ sub: 'hang-me', roles: ['technician'] }));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const timers = () => process.getActiveResourcesInfo().filter((r) => r === 'Timeout').length;

const unhandled = [];
const onU = (e) => unhandled.push(e);
process.on('unhandledRejection', onU);
test.after(() => { process.off('unhandledRejection', onU); assert.deepEqual(unhandled.map(String), []); });

// Hangs only for tokens whose sub is "hang-me"; otherwise delegates to the real verifier.
const selective = { name: 'selective', verify: async (t) => { const c = await real.verify(t); if (c.sub === 'hang-me') await new Promise(() => {}); return c; } };

test('timeout under load: 300 concurrent hung auths all get 503 within the bound; healthy tokens are unaffected', async (t) => {
  const s = await startServer({ provider: selective, app: { authTimeoutMs: 150 } }); t.after(() => s.close());
  const t0 = Date.now();
  const res = await Promise.all(Array.from({ length: 300 }, (_, i) => raw(s.port, { path: '/proxy/x', headers: bearer(i % 3 ? hungTok : tech) })));
  const elapsed = Date.now() - t0;
  for (const [i, r] of res.entries()) {
    if (i % 3) {
      assert.equal(r.status, 503, `#${i}`);
      assert.deepEqual(r.json, { error: 'auth_unavailable' });
      assert.equal(r.headers['retry-after'], '5');
      assert.equal(r.headers['www-authenticate'], undefined, '503 is not an auth challenge');
    } else assert.equal(r.status, 200, `#${i}`);
  }
  assert.ok(elapsed < 3000, `took ${elapsed} ms`);
  const audit = s.app.audit.recent(100000);
  assert.equal(audit.filter((e) => e.type === 'auth.unavailable').length, 200);
  assert.ok(!audit.some((e) => e.type === 'auth.unavailable' && e.actor), 'no actor is attributed to an unverified token');
});

test('timeout: timers return to baseline after hung, slow and fast auths (no timer leak)', async (t) => {
  const s = await startServer({ provider: selective, app: { authTimeoutMs: 80 } }); t.after(() => s.close());
  await raw(s.port, { path: '/health' });
  const base = timers();
  await Promise.all(Array.from({ length: 60 }, (_, i) => raw(s.port, { path: '/proxy/y', headers: bearer(i % 2 ? hungTok : tech) })));
  await sleep(50);
  assert.ok(timers() <= base + 1, `timers ${timers()} vs ${base}`);
});

test('timeout: a provider that resolves or rejects AFTER the deadline changes nothing and raises nothing', async (t) => {
  let n = 0;
  const late = { name: 'late', verify: async (tk) => { const i = n++; await sleep(120); if (i % 2) throw new Error('late failure'); return real.verify(tk); } };
  const s = await startServer({ provider: late, app: { authTimeoutMs: 40 } }); t.after(() => s.close());
  const res = await Promise.all(Array.from({ length: 20 }, () => raw(s.port, { path: '/admin/audit', headers: bearer(tech) })));
  assert.ok(res.every((r) => r.status === 503));
  await sleep(200);
  assert.equal(s.app.audit.recent(1000).filter((e) => e.type === 'request' || e.type === 'authz.denied').length, 0, 'late results never applied');
});

test('timeout boundary: a provider just under the deadline succeeds, just over it fails', async (t) => {
  const delayed = (ms) => ({ name: 'd', verify: async (tk) => { await sleep(ms); return real.verify(tk); } });
  for (const [ms, timeout, want] of [[10, 300, 200], [400, 100, 503]]) {
    const s = await startServer({ provider: delayed(ms), app: { authTimeoutMs: timeout } });
    assert.equal((await raw(s.port, { path: '/proxy/z', headers: bearer(tech) })).status, want, `${ms}/${timeout}`);
    await s.close();
  }
  assert.ok(t);
});

test('retries: the proxy never retries a provider; a flaky provider gives exactly one result per request', async (t) => {
  let calls = 0;
  const flaky = { name: 'flaky', verify: async (tk) => { calls++; if (calls % 2) throw new Error('transient'); return real.verify(tk); } };
  const s = await startServer({ provider: flaky }); t.after(() => s.close());
  const st = [];
  for (let i = 0; i < 10; i++) st.push((await raw(s.port, { path: '/proxy/x', headers: bearer(tech) })).status);
  assert.equal(calls, 10, 'one verify call per request');
  assert.deepEqual(st, [401, 200, 401, 200, 401, 200, 401, 200, 401, 200]);
});

test('races: the same token verified concurrently with random provider latency yields identical, independent results', async (t) => {
  let seed = 7;
  const jitter = { name: 'j', verify: async (tk) => { seed = (seed * 48271) % 2147483647; await sleep(seed % 25); return real.verify(tk); } };
  const s = await startServer({ provider: jitter, app: { authTimeoutMs: 1000 } }); t.after(() => s.close());
  const toks = ['a', 'b', 'c', 'd'].map((sub) => [sub, sign(claims({ sub, roles: ['technician'] }))]);
  const res = await Promise.all(Array.from({ length: 120 }, (_, i) => { const [sub, tk] = toks[i % 4]; return raw(s.port, { path: '/proxy/x', headers: bearer(tk) }).then((r) => [sub, r]); }));
  for (const [sub, r] of res) { assert.equal(r.status, 200); assert.equal(r.json.principal, sub, 'no cross-request identity bleed'); }
});

test('authTimeoutMs flows from createApp to the authenticator and is validated there', () => {
  const { createApp } = require('../src/server');
  for (const bad of [0, -5, 1.5, 60001, '100']) assert.throws(() => createApp({ provider: real, authTimeoutMs: bad }), /Auth timeout/, String(bad));
  assert.doesNotThrow(() => createApp({ provider: real, authTimeoutMs: 1 }));
  assert.doesNotThrow(() => createApp({ provider: real, authTimeoutMs: 60000 }));
});
