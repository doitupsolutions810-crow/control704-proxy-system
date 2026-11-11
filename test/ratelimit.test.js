'use strict';
// rateLimitPerMinute is CONFIGURATION ONLY in the current code: it is validated, stored,
// returned and revertible, but NOT enforced (no request counting). These tests lock in that
// the config is honoured end to end and document clearly that enforcement is absent.
const test = require('node:test');
const assert = require('node:assert');
const { DatasetStore } = require('../src/datasets/store');
const { sign, claims, startServer, raw, bearer, jsonPost } = require('./helpers');

const ctx = { actor: 'a', reason: 'rate limit test' };

test('boundaries: 1 and 10000 accepted, 0 and 10001 rejected, per route independently', () => {
  for (const id of ['X', 'Y', 'Z']) {
    const s = new DatasetStore();
    assert.equal(s.override(id, { rateLimitPerMinute: 1 }, ctx).after.rateLimitPerMinute, 1);
    assert.equal(s.override(id, { rateLimitPerMinute: 10000 }, ctx).after.rateLimitPerMinute, 10000);
    assert.throws(() => s.override(id, { rateLimitPerMinute: 0 }, ctx));
    assert.throws(() => s.override(id, { rateLimitPerMinute: 10001 }, ctx));
    for (const other of ['X', 'Y', 'Z'].filter((o) => o !== id)) assert.equal(s.get(other).rateLimitPerMinute, 60);
  }
});
test('config is honoured end-to-end: /proxy/<id> profile reflects the per-route limit, revert restores it', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const admin = sign(claims({ roles: ['admin'] }));
  const set = async (id, v) => (await raw(s.port, { path: `/admin/datasets/${id}/overrides`, ...jsonPost(admin, { patch: { rateLimitPerMinute: v }, reason: 'rate limit' }) })).json;
  const rx = await set('X', 1); await set('Y', 10000);
  const prof = async (id) => (await raw(s.port, { path: `/proxy/${id}`, headers: bearer(admin) })).json.profile.rateLimitPerMinute;
  assert.equal(await prof('x'), 1); assert.equal(await prof('y'), 10000); assert.equal(await prof('z'), 60);
  await raw(s.port, { method: 'POST', path: `/admin/overrides/${rx.id}/revert`, headers: bearer(admin) });
  assert.equal(await prof('x'), 60);
});
test('NOT ENFORCED (current behaviour): with rateLimitPerMinute=1, 25 requests in the same minute all succeed', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const admin = sign(claims({ roles: ['admin'] }));
  await raw(s.port, { path: '/admin/datasets/X/overrides', ...jsonPost(admin, { patch: { rateLimitPerMinute: 1 }, reason: 'rate limit 1' }) });
  const tech = sign(claims({ roles: ['technician'] }));
  const statuses = [];
  for (let i = 0; i < 25; i++) statuses.push((await raw(s.port, { path: '/proxy/x', headers: bearer(tech) })).status);
  assert.ok(statuses.every((x) => x === 200), 'CURRENT: no 429s — enforcement is not implemented');
  assert.ok(!statuses.includes(429));
});
test('window rollover: not applicable while enforcement is absent — a fake-clock minute boundary changes nothing', async (t) => {
  const { createAvroneProvider } = require('../src/auth/avroneProvider');
  const { config, fakeClock } = require('./helpers');
  const c = fakeClock(Math.floor(Date.now() / 60000) * 60000 + 59_900); // 100ms before a minute boundary
  const s = await startServer({ provider: createAvroneProvider({ ...config, now: c.now }) });
  t.after(() => s.close());
  const nowS = c.now() / 1000;
  const tech = sign({ iss: config.issuer, aud: config.audience, sub: 't', iat: Math.floor(nowS) - 1, exp: nowS + 600, roles: ['technician'] });
  const a = await Promise.all(Array.from({ length: 5 }, () => raw(s.port, { path: '/proxy/y', headers: bearer(tech) })));
  c.advance(200);
  const b = await Promise.all(Array.from({ length: 5 }, () => raw(s.port, { path: '/proxy/y', headers: bearer(tech) })));
  assert.ok([...a, ...b].every((r) => r.status === 200));
});
