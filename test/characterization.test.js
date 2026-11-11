'use strict';
// CHARACTERIZATION TESTS — they document CURRENT behaviour for decisions Jean has not made yet.
// They are deliberately NOT a statement that the behaviour is desired. If the policy changes,
// update these tests together with the code.
const test = require('node:test');
const assert = require('node:assert');
const { DatasetStore } = require('../src/datasets/store');
const { sign, claims, startServer, raw, bearer, jsonPost } = require('./helpers');

// ---------- Open question 1: scope-only token can override without admin role ----------
test('OPEN-Q1 (current behaviour): a token with scope "datasets:override" and NO admin role CAN create overrides', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const scopeOnly = sign(claims({ sub: 'svc-bot', scope: 'datasets:override' }));
  const r = await raw(s.port, { path: '/admin/datasets/X/overrides', ...jsonPost(scopeOnly, { patch: { enabled: false }, reason: 'scope only' }) });
  assert.equal(r.status, 201, 'CURRENT: scope-only override allowed (pending decision)');
  assert.equal(r.json.actor, 'svc-bot');
});
test('OPEN-Q1 (current behaviour): scope-only "datasets:revert" can revert; "audit:read" can read history', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const ov = sign(claims({ scope: 'datasets:override' }));
  const rec = (await raw(s.port, { path: '/admin/datasets/Y/overrides', ...jsonPost(ov, { patch: { enabled: false }, reason: 'q1 check' }) })).json;
  assert.ok(rec.id, JSON.stringify(rec));
  assert.equal((await raw(s.port, { method: 'POST', path: `/admin/overrides/${rec.id}/revert`, headers: bearer(sign(claims({ scope: 'datasets:revert' }))) })).status, 200);
  assert.equal((await raw(s.port, { path: '/admin/datasets/Y/overrides', headers: bearer(sign(claims({ scope: 'audit:read' }))) })).status, 200);
});
test('OPEN-Q1 (current behaviour): a viewer role PLUS a datasets:override scope can override', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await raw(s.port, { path: '/admin/datasets/Z/overrides', ...jsonPost(sign(claims({ roles: ['viewer'], scope: 'datasets:override' })), { patch: { enabled: false }, reason: 'viewer+scope' }) });
  assert.equal(r.status, 201);
});

// ---------- Open question 2: internal / private upstream addresses ----------
const INTERNAL = [
  'http://127.0.0.1:8080', 'http://localhost/', 'http://localhost.localdomain/', 'http://[::1]/', 'http://0.0.0.0/',
  'http://10.0.0.5/', 'http://172.16.0.1/', 'http://192.168.1.1/', 'http://169.254.169.254/latest/meta-data/',
  'http://[fd00::1]/', 'http://[fe80::1]/', 'http://[::ffff:127.0.0.1]/', 'http://2130706433/' /* 127.0.0.1 as integer */,
  'http://0x7f000001/', 'http://017700000001/' /* octal */, 'http://127.1/', 'http://metadata.google.internal/', 'http://100.64.0.1/',
];
for (const u of INTERNAL) {
  test(`OPEN-Q2 (current behaviour): internal upstream ${u} is ACCEPTED`, () => {
    const r = new DatasetStore().override('X', { upstream: u }, { actor: 'a', reason: 'internal upstream' });
    assert.equal(r.after.upstream, u, 'CURRENT: private/loopback/metadata upstreams allowed (pending decision)');
  });
}
test('OPEN-Q2 note: stored upstream is the raw string (WHATWG URL would normalise 2130706433 -> 127.0.0.1)', () => {
  assert.equal(new URL('http://2130706433/').hostname, '127.0.0.1');
  assert.equal(new URL('http://0x7f000001/').hostname, '127.0.0.1');
  assert.equal(new URL('http://127.1/').hostname, '127.0.0.1');
});
test('OPEN-Q2 note: upstream is config only — the proxy never connects to it today, so there is no live SSRF path yet', async (t) => {
  const http = require('http');
  let hits = 0;
  const sink = http.createServer((q, r) => { hits++; r.end('hit'); });
  await new Promise((r) => sink.listen(0, '127.0.0.1', r));
  const s = await startServer();
  t.after(() => { s.close(); sink.close(); });
  const admin = sign(claims({ roles: ['admin'] }));
  await raw(s.port, { path: '/admin/datasets/X/overrides', ...jsonPost(admin, { patch: { upstream: `http://127.0.0.1:${sink.address().port}/` }, reason: 'ssrf probe' }) });
  const r = await raw(s.port, { path: '/proxy/x', headers: bearer(admin) });
  assert.equal(r.status, 200);
  assert.equal(hits, 0);
});
